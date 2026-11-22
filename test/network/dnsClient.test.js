// Integration tests: real UDP and TCP sockets against a scripted DNS server
// on 127.0.0.1, so no public DNS is needed.
import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";

import { DNSClient, validateResponse } from "../../src/resolver/dnsClient.js";
import { sendDNSQuery } from "../../src/network/udpClient.js";
import { parseDNSMessage } from "../../src/dns/decoder/parseDNSMessage.js";
import { buildQuery } from "../../src/dns/encoder/buildQuery.js";
import { buildResponse, A, QR, TC } from "../helpers/dnsPacket.js";

/**
 * Start UDP + TCP listeners on the same port.
 * `onUdp(query, reply)` / `onTcp(query, reply)` decide what to send back.
 */
async function startServer({ onUdp = () => {}, onTcp = () => {} } = {}) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const udp = dgram.createSocket("udp4");
    await new Promise((resolve) => udp.bind(0, "127.0.0.1", resolve));
    const { port } = udp.address();

    const tcp = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length < 2 || buffer.length < 2 + buffer.readUInt16BE(0)) return;
        const query = parseDNSMessage(buffer.subarray(2, 2 + buffer.readUInt16BE(0)));
        onTcp(query, (bytes) => {
          const prefix = Buffer.alloc(2);
          prefix.writeUInt16BE(bytes.length, 0);
          socket.end(Buffer.concat([prefix, bytes]));
        });
      });
      socket.on("error", () => {});
    });

    try {
      await new Promise((resolve, reject) => {
        tcp.once("error", reject);
        tcp.listen(port, "127.0.0.1", resolve);
      });
    } catch {
      udp.close();
      continue; // TCP port taken; try another
    }

    udp.on("message", (bytes, remote) => {
      onUdp(parseDNSMessage(bytes), (reply) => udp.send(reply, remote.port, remote.address));
    });

    return {
      port,
      close: () => {
        udp.close();
        tcp.close();
      },
    };
  }
  throw new Error("could not bind test server");
}

const answerFor = (query, extra = {}) =>
  buildResponse({
    id: query.id,
    question: query.questions[0],
    answers: [A(query.questions[0].name, "192.0.2.1")],
    ...extra,
  });

test("UDP: returns a validated response", async (t) => {
  const server = await startServer({ onUdp: (q, reply) => reply(answerFor(q)) });
  t.after(server.close);

  const message = await new DNSClient({ port: server.port }).query("example.com", "127.0.0.1");
  assert.equal(message.answers[0].data, "192.0.2.1");
});

test("UDP: a spoofed reply with the wrong ID is ignored; the real one is accepted", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => {
      reply(answerFor({ ...q, id: (q.id + 1) & 0xffff }, { answers: [A("example.com", "6.6.6.6")] }));
      setTimeout(() => reply(answerFor(q)), 20);
    },
  });
  t.after(server.close);

  const message = await new DNSClient({ port: server.port }).query("example.com", "127.0.0.1");
  assert.equal(message.answers[0].data, "192.0.2.1");
});

test("UDP: transaction IDs above 0x7fff are matched correctly", async (t) => {
  const server = await startServer({ onUdp: (q, reply) => reply(answerFor(q)) });
  t.after(server.close);

  const { packet } = buildQuery("example.com", 1, false);
  packet.writeUInt16BE(0xfff0, 0);
  const response = await sendDNSQuery(packet, "127.0.0.1", server.port, 1000);
  assert.equal(response.readUInt16BE(0), 0xfff0);
});

test("UDP: a response for a different question is rejected", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { question: { name: "evil.com" } })),
  });
  t.after(server.close);

  await assert.rejects(
    new DNSClient({ port: server.port }).query("example.com", "127.0.0.1"),
    /question does not match/,
  );
});

test("UDP: times out when the server never answers", async (t) => {
  const server = await startServer();
  t.after(server.close);

  await assert.rejects(
    new DNSClient({ port: server.port, timeout: 200 }).query("example.com", "127.0.0.1"),
    /timed out/,
  );
});

test("UDP: SERVFAIL and REFUSED are errors; NXDOMAIN is returned to the caller", async (t) => {
  let rcode = 2;
  const server = await startServer({ onUdp: (q, reply) => reply(answerFor(q, { rcode, answers: [] })) });
  t.after(server.close);
  const client = new DNSClient({ port: server.port });

  await assert.rejects(client.query("example.com", "127.0.0.1"), /RCODE 2/);
  rcode = 5;
  await assert.rejects(client.query("example.com", "127.0.0.1"), /RCODE 5/);
  rcode = 3;
  assert.equal((await client.query("example.com", "127.0.0.1")).responseCode, 3);
});

test("TCP fallback: a truncated UDP answer is retried over TCP", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { flags: QR | TC, answers: [] })),
    onTcp: (q, reply) => reply(answerFor(q)),
  });
  t.after(server.close);

  const message = await new DNSClient({ port: server.port }).query("example.com", "127.0.0.1");
  assert.equal(message.truncated, false);
  assert.equal(message.answers[0].data, "192.0.2.1");
});

test("TCP fallback: the TCP answer is validated like the UDP one", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { flags: QR | TC, answers: [] })),
    onTcp: (q, reply) => reply(answerFor(q, { question: { name: "evil.com" } })),
  });
  t.after(server.close);

  await assert.rejects(
    new DNSClient({ port: server.port }).query("example.com", "127.0.0.1"),
    /question does not match/,
  );
});

test("TCP fallback: a TCP answer that is a query (QR clear) is rejected", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { flags: QR | TC, answers: [] })),
    onTcp: (q, reply) => reply(answerFor(q, { flags: 0 })),
  });
  t.after(server.close);

  await assert.rejects(
    new DNSClient({ port: server.port }).query("example.com", "127.0.0.1"),
    /instead of a response/,
  );
});

test("TCP fallback: a TCP answer that is still truncated is an error", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { flags: QR | TC, answers: [] })),
    onTcp: (q, reply) => reply(answerFor(q, { flags: QR | TC })),
  });
  t.after(server.close);

  await assert.rejects(
    new DNSClient({ port: server.port }).query("example.com", "127.0.0.1"),
    /still truncated/,
  );
});

test("TCP: a server that closes without a full answer is an error", async (t) => {
  const server = await startServer({
    onUdp: (q, reply) => reply(answerFor(q, { flags: QR | TC, answers: [] })),
    onTcp: (q, reply) => reply(Buffer.alloc(0)),
  });
  t.after(server.close);

  await assert.rejects(new DNSClient({ port: server.port }).query("example.com", "127.0.0.1"));
});

test("network errors surface as rejections (nothing listening)", async () => {
  const probe = dgram.createSocket("udp4");
  await new Promise((resolve) => probe.bind(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  probe.close();

  // ICMP port-unreachable shows up as an error or, on some systems, a timeout.
  await assert.rejects(new DNSClient({ port, timeout: 300 }).query("example.com", "127.0.0.1"));
});

test("validateResponse rejects missing questions", () => {
  const message = parseDNSMessage(buildResponse({ id: 7, question: null }));
  assert.throws(
    () => validateResponse(message, { id: 7, domain: "example.com", type: 1 }),
    /question/,
  );
});
