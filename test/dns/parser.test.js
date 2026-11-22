import test from "node:test";
import assert from "node:assert/strict";

import { parseDNSMessage } from "../../src/dns/decoder/parseDNSMessage.js";
import { DNS_TYPES } from "../../src/dns/constants.js";
import { buildResponse, A, NS, CNAME, QR, AA, TC } from "../helpers/dnsPacket.js";

test("parses header flags and response code", () => {
  const message = parseDNSMessage(
    buildResponse({ id: 0xbeef, flags: QR | AA | TC, rcode: 3 }),
  );

  assert.equal(message.id, 0xbeef);
  assert.equal(message.isResponse, true);
  assert.equal(message.authoritative, true);
  assert.equal(message.truncated, true);
  assert.equal(message.recursionDesired, false);
  assert.equal(message.responseCode, 3);
});

test("parses A, NS, CNAME and AAAA records into the right sections", () => {
  const message = parseDNSMessage(
    buildResponse({
      answers: [CNAME("www.example.com", "example.com"), A("example.com", "93.184.215.14", 120)],
      authorities: [NS("example.com", "a.iana-servers.net")],
      additionals: [
        { name: "a.iana-servers.net", type: DNS_TYPES.AAAA, data: "2001:500:8f:0:0:0:0:53", ttl: 60 },
      ],
    }),
  );

  assert.deepEqual(
    message.answers.map((r) => [r.type, r.name, r.data, r.ttl]),
    [
      [5, "www.example.com", "example.com", 300],
      [1, "example.com", "93.184.215.14", 120],
    ],
  );
  assert.equal(message.authorities[0].data, "a.iana-servers.net");
  assert.equal(message.additionals[0].data, "2001:500:8f:0:0:0:0:53");
});

test("decodes compressed names inside RDATA", () => {
  // header (1 question, 1 answer) + question example.com A IN
  // + answer: name ptr->12, CNAME, rdata "www" + ptr->12
  const question = Buffer.from("076578616d706c6503636f6d0000010001", "hex");
  const answer = Buffer.from([
    0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 119, 119, 119, 0xc0, 0x0c,
  ]);
  const header = Buffer.from([0, 1, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0]);

  const message = parseDNSMessage(Buffer.concat([header, question, answer]));

  assert.equal(message.answers[0].name, "example.com");
  assert.equal(message.answers[0].data, "www.example.com");
});

test("TTLs with the top bit set are treated as zero (RFC 2181 §8)", () => {
  const message = parseDNSMessage(
    buildResponse({ answers: [A("example.com", "1.2.3.4", 0x80000000)] }),
  );
  assert.equal(message.answers[0].ttl, 0);
});

test("NS RDATA whose name does not fill RDLENGTH exactly is rejected", () => {
  const packet = buildResponse({ answers: [NS("example.com", "ns.example.com")] });
  // grow RDLENGTH by one and append a junk byte
  const rdlengthOffset = packet.length - encodeLength("ns.example.com") - 2;
  packet.writeUInt16BE(packet.readUInt16BE(rdlengthOffset) + 1, rdlengthOffset);
  assert.throws(() => parseDNSMessage(Buffer.concat([packet, Buffer.from([0])])), /RDATA/);
});

function encodeLength(name) {
  return name.split(".").reduce((sum, label) => sum + label.length + 1, 1);
}

test("A and AAAA records with the wrong RDLENGTH are rejected", () => {
  assert.throws(
    () => parseDNSMessage(buildResponse({ answers: [{ name: "x", type: 1, data: [1, 2, 3] }] })),
    /IPv4/,
  );
  assert.throws(
    () => parseDNSMessage(buildResponse({ answers: [{ name: "x", type: 28, data: [1, 2, 3] }] })),
    /IPv6/,
  );
});

test("a header that promises more records than present fails", () => {
  const packet = buildResponse({ answers: [A("example.com", "1.2.3.4")] });
  packet.writeUInt16BE(2, 6); // ANCOUNT = 2
  assert.throws(() => parseDNSMessage(packet));
});

test("packets shorter than a header fail", () => {
  assert.throws(() => parseDNSMessage(Buffer.alloc(11)), /header/);
});

test("every truncation of a valid packet throws an Error and never hangs", () => {
  const packet = buildResponse({
    answers: [CNAME("www.example.com", "example.com"), A("example.com", "1.2.3.4")],
    authorities: [NS("example.com", "ns1.example.com")],
    additionals: [A("ns1.example.com", "5.6.7.8")],
  });

  for (let length = 0; length < packet.length; length++) {
    assert.throws(() => parseDNSMessage(packet.subarray(0, length)), Error);
  }
});

test("random garbage never crashes with a non-Error or loops forever", () => {
  let seed = 12345;
  const random = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);

  for (let i = 0; i < 2000; i++) {
    const packet = Buffer.from(
      Array.from({ length: 12 + Math.floor(random() * 80) }, () => Math.floor(random() * 256)),
    );
    try {
      parseDNSMessage(packet);
    } catch (error) {
      assert.ok(error instanceof Error);
    }
  }
});
