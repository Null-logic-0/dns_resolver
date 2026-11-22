import test from "node:test";
import assert from "node:assert/strict";

import { buildQuery } from "../../src/dns/encoder/buildQuery.js";
import { parseDNSMessage } from "../../src/dns/decoder/parseDNSMessage.js";
import { DNS_TYPES } from "../../src/dns/constants.js";

test("builds a recursive query by default", () => {
  const { id, packet } = buildQuery("dns.facebook.com");

  assert.equal(packet.readUInt16BE(0), id);
  assert.equal(packet.readUInt16BE(2), 0x0100);
  assert.equal(packet.readUInt16BE(4), 1);
  assert.equal(packet.readUInt16BE(6), 0);
  assert.equal(packet.readUInt16BE(8), 0);
  assert.equal(packet.readUInt16BE(10), 0);
});

test("builds an iterative query (RD clear) with the right question", () => {
  const { id, packet } = buildQuery("Example.COM", DNS_TYPES.AAAA, false);
  const message = parseDNSMessage(packet);

  assert.equal(message.id, id);
  assert.equal(message.flags, 0);
  assert.deepEqual(message.questions, [
    { name: "Example.COM", type: DNS_TYPES.AAAA, class: 1 },
  ]);
});

test("transaction IDs use the full 16-bit range", () => {
  for (let i = 0; i < 500; i++) {
    const { id } = buildQuery("example.com");
    assert.ok(Number.isInteger(id) && id >= 0 && id <= 0xffff);
  }
});
