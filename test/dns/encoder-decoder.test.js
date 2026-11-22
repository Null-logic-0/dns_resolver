import test from "node:test";
import assert from "node:assert/strict";

import { encodeDomainName } from "../../src/dns/encoder/encodeDomainName.js";

import { decodeDomainName } from "../../src/dns/decoder/decodeDomainName.js";

test("domain encoding", () => {
  const encoded = encodeDomainName("example.com");

  assert.equal(encoded.toString("hex"), "076578616d706c6503636f6d00");
});

test("domain decoding", () => {
  const encoded = encodeDomainName("example.com");

  const packet = Buffer.concat([Buffer.alloc(12), encoded]);

  const decoded = decodeDomainName(packet, 12);

  assert.equal(decoded.name, "example.com");
});

test("compression pointer decoding", () => {
  const packet = Buffer.from([
    ...Buffer.alloc(12),
    3,
    119,
    119,
    119,
    0,
    0xc0,
    0x0c,
  ]);

  const decoded = decodeDomainName(packet, 17);

  assert.equal(decoded.name, "www");
  assert.equal(decoded.offset, 19);
});

// --- encoding edge cases ---------------------------------------------------

test("encoding: a trailing dot (fully qualified name) is accepted", () => {
  assert.equal(
    encodeDomainName("example.com.").toString("hex"),
    "076578616d706c6503636f6d00",
  );
});

test("encoding: the root name is a single zero byte", () => {
  assert.equal(encodeDomainName("").toString("hex"), "00");
  assert.equal(encodeDomainName(".").toString("hex"), "00");
});

test("encoding: empty labels are rejected", () => {
  assert.throws(() => encodeDomainName("a..com"), /empty label/);
  assert.throws(() => encodeDomainName(".com"), /empty label/);
});

test("encoding: non-ASCII labels are rejected instead of being mangled", () => {
  assert.throws(() => encodeDomainName("münchen.de"), /ASCII/);
});

test("encoding: 63-byte labels pass, 64-byte labels fail", () => {
  assert.doesNotThrow(() => encodeDomainName(`${"a".repeat(63)}.com`));
  assert.throws(() => encodeDomainName(`${"a".repeat(64)}.com`), /63/);
});

test("encoding: names longer than 255 bytes on the wire fail", () => {
  const label = "a".repeat(63);
  // 4 * 64 + 1 = 257 bytes
  assert.throws(
    () => encodeDomainName([label, label, label, label].join(".")),
    /255/,
  );
});

// decoding edge cases

test("decoding: the root name decodes to an empty string", () => {
  const decoded = decodeDomainName(Buffer.from([0]), 0);
  assert.deepEqual(decoded, { name: "", offset: 1 });
});

test("decoding: a pointer that points at itself is a loop", () => {
  const packet = Buffer.from([...Buffer.alloc(12), 0xc0, 0x0c]);
  assert.throws(() => decodeDomainName(packet, 12), /loop/);
});

test("decoding: a two-pointer cycle is a loop", () => {
  // offset 12 -> 14 -> 12
  const packet = Buffer.from([...Buffer.alloc(12), 0xc0, 0x0e, 0xc0, 0x0c]);
  assert.throws(() => decodeDomainName(packet, 12), /loop/);
});

test("decoding: a pointer past the end of the packet fails", () => {
  const packet = Buffer.from([...Buffer.alloc(12), 0xc0, 0xff]);
  assert.throws(() => decodeDomainName(packet, 12), /pointer/);
});

test("decoding: a label running past the packet fails", () => {
  const packet = Buffer.from([...Buffer.alloc(12), 5, 97, 98]);
  assert.throws(() => decodeDomainName(packet, 12), /boundaries/);
});

test("decoding: a name with no terminating zero fails", () => {
  const packet = Buffer.from([...Buffer.alloc(12), 1, 97]);
  assert.throws(() => decodeDomainName(packet, 12), /boundaries/);
});

test("decoding: reserved label types (0x40, 0x80) fail", () => {
  assert.throws(() => decodeDomainName(Buffer.from([0x40, 0]), 0), /label/);
  assert.throws(() => decodeDomainName(Buffer.from([0x80, 0]), 0), /label/);
});

test("decoding: names longer than 255 bytes fail, even via pointers", () => {
  // five 63-byte labels chained through pointers = far over 255 bytes
  const parts = [];
  const label = [63, ...Buffer.alloc(63, 97)];
  for (let i = 0; i < 5; i++) {
    const nextOffset = (i + 1) * 66;
    parts.push(...label, 0xc0, nextOffset);
  }
  parts.push(0);
  assert.throws(() => decodeDomainName(Buffer.from(parts), 0), /255/);
});
