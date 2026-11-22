import test from "node:test";
import assert from "node:assert/strict";

import { DNSCache } from "../../src/resolver/cache.js";

test("stores values until their TTL expires", () => {
  let now = 1_000_000;
  const cache = new DNSCache({ now: () => now });

  cache.set("example.com/A", "value", 60);
  assert.equal(cache.get("example.com/A"), "value");

  now += 59_999;
  assert.deepEqual(cache.getWithAge("example.com/A"), { value: "value", age: 59 });

  now += 1;
  assert.equal(cache.get("example.com/A"), null);
  assert.equal(cache.size, 0, "expired entries are evicted");
});

test("does not store zero, negative, or missing TTLs", () => {
  const cache = new DNSCache();
  cache.set("a", 1, 0);
  cache.set("b", 1, -5);
  cache.set("c", 1, undefined);
  cache.set("d", 1, Infinity - Infinity);
  assert.equal(cache.size, 0);
});
