// End-to-end: real DNSResolver + DNSClient + UDP/TCP sockets + parser against
// three fake DNS servers (root, TLD, authoritative) on separate loopback IPs.
// Needs 127.0.0.2/127.0.0.3: available by default on Linux, not on macOS
// (there the test is skipped; enable with
//  `sudo ifconfig lo0 alias 127.0.0.2 up && sudo ifconfig lo0 alias 127.0.0.3 up`).
import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";

import { DNSResolver } from "../../src/resolver/dnsResolver.js";
import { DNSClient } from "../../src/resolver/dnsClient.js";
import { parseDNSMessage } from "../../src/dns/decoder/parseDNSMessage.js";
import { buildResponse, A, NS, CNAME, QR, AA, TC } from "../helpers/dnsPacket.js";
import { silentLogger } from "../helpers/mockNetwork.js";

const ROOT = "127.0.0.1";
const TLD = "127.0.0.2";
const AUTH = "127.0.0.3";

async function canBind(host) {
  const socket = dgram.createSocket("udp4");
  try {
    await new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(0, host, resolve);
    });
    return true;
  } catch {
    return false;
  } finally {
    try { socket.close(); } catch {}
  }
}

/** Serve `answer(name, transport) => spec` over UDP and TCP on host:port. */
async function serve(host, port, answer, log) {
  const reply = (bytes, transport) => {
    const query = parseDNSMessage(bytes);
    const name = query.questions[0].name;
    log.push(`${host} ${transport} ${name}`);
    return buildResponse({ id: query.id, question: query.questions[0], ...answer(name, transport) });
  };

  const udp = dgram.createSocket("udp4");
  udp.on("message", (bytes, remote) => udp.send(reply(bytes, "udp"), remote.port, remote.address));
  await new Promise((resolve, reject) => {
    udp.once("error", reject);
    udp.bind(port, host, resolve);
  });

  const tcp = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("error", () => {});
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 2 || buffer.length < 2 + buffer.readUInt16BE(0)) return;
      const out = reply(buffer.subarray(2, 2 + buffer.readUInt16BE(0)), "tcp");
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(out.length, 0);
      socket.end(Buffer.concat([prefix, out]));
    });
  });
  await new Promise((resolve, reject) => {
    tcp.once("error", reject);
    tcp.listen(port, host, resolve);
  });

  return () => {
    udp.close();
    tcp.close();
  };
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

const loopbackAliases = (await canBind(TLD)) && (await canBind(AUTH));

test(
  "resolves through root -> TLD -> authoritative over real sockets, with TCP fallback and a CNAME",
  { skip: !loopbackAliases && "127.0.0.2/127.0.0.3 not configured on this machine" },
  async (t) => {
    const port = await freePort();
    const log = [];

    const closers = [
      // Root: answers UDP with TC=1 (like the real root did without EDNS),
      // full referral only over TCP.
      await serve(ROOT, port, (name, transport) =>
        transport === "udp"
          ? { flags: QR | TC }
          : { authorities: [NS("test", "ns.nic.test")], additionals: [A("ns.nic.test", TLD)] },
      log),
      await serve(TLD, port, () => ({
        authorities: [NS("example.test", "ns1.example.test")],
        additionals: [A("ns1.example.test", AUTH), A("evil.test", "6.6.6.6")],
      }), log),
      await serve(AUTH, port, (name) =>
        name === "www.example.test"
          ? { flags: QR | AA, answers: [CNAME("www.example.test", "web.example.test", 30)] }
          : { flags: QR | AA, answers: [A("web.example.test", "192.0.2.80", 300)] },
      log),
    ];
    t.after(() => closers.forEach((close) => close()));

    const resolver = new DNSResolver({
      rootServers: [ROOT],
      client: new DNSClient({ port, timeout: 1000 }),
      logger: silentLogger,
    });

    const result = await resolver.resolve("www.example.test");

    assert.deepEqual(result, {
      domain: "www.example.test",
      resolvedName: "web.example.test",
      cnames: [{ name: "www.example.test", target: "web.example.test", ttl: 30 }],
      addresses: [{ address: "192.0.2.80", ttl: 300 }],
    });

    assert.deepEqual(log, [
      `${ROOT} udp www.example.test`,
      `${ROOT} tcp www.example.test`,
      `${TLD} udp www.example.test`,
      `${AUTH} udp www.example.test`,
      `${ROOT} udp web.example.test`,
      `${ROOT} tcp web.example.test`,
      `${TLD} udp web.example.test`,
      `${AUTH} udp web.example.test`,
    ]);

    // Second lookup is served from cache: no new packets.
    const before = log.length;
    assert.equal((await resolver.resolve("www.example.test")).fromCache, true);
    assert.equal(log.length, before);
  },
);
