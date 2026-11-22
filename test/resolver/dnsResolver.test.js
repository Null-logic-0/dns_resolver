import test from "node:test";
import assert from "node:assert/strict";

import { DNSResolver } from "../../src/resolver/dnsResolver.js";
import { DNSCache } from "../../src/resolver/cache.js";
import { A, NS, CNAME, AA } from "../helpers/dnsPacket.js";
import { mockClient, silentLogger } from "../helpers/mockNetwork.js";

const ROOT = "198.41.0.4";
const COM = "192.5.6.30";
const NET = "192.12.94.30";
const EXAMPLE_NS = "199.43.135.53";

const authoritative = (answers) => ({ flags: 0x8000 | AA, answers });

function standardHierarchy(overrides = {}) {
  return {
    [ROOT]: (domain) =>
      domain.endsWith(".net")
        ? {
            authorities: [NS("net", "a.gtld-servers.net")],
            additionals: [A("a.gtld-servers.net", NET)],
          }
        : {
            authorities: [NS("com", "a.gtld-servers.net")],
            additionals: [A("a.gtld-servers.net", COM)],
          },
    [COM]: () => ({
      authorities: [
        NS("example.com", "a.iana-servers.net"),
        NS("example.com", "ns.example.com"),
      ],
      additionals: [A("ns.example.com", EXAMPLE_NS)],
    }),
    [EXAMPLE_NS]: (domain) =>
      domain === "example.com"
        ? authoritative([A("example.com", "93.184.215.14", 120)])
        : { flags: 0x8000 | AA, rcode: 3 },
    ...overrides,
  };
}

function makeResolver(servers, options = {}) {
  const client = mockClient(servers);
  const resolver = new DNSResolver({
    rootServers: [ROOT],
    client,
    logger: silentLogger,
    ...options,
  });
  return { resolver, client };
}

test("walks root -> TLD -> authoritative and returns address + TTL", async () => {
  const { resolver, client } = makeResolver(standardHierarchy());

  const result = await resolver.resolve("Example.COM.");

  assert.deepEqual(result, {
    domain: "example.com",
    resolvedName: "example.com",
    cnames: [],
    addresses: [{ address: "93.184.215.14", ttl: 120 }],
  });
  assert.deepEqual(client.calls, [
    `${ROOT} example.com`,
    `${COM} example.com`,
    `${EXAMPLE_NS} example.com`,
  ]);
});

test("falls back to the next root server when one fails", async () => {
  const { resolver, client } = makeResolver(
    standardHierarchy({ "10.0.0.1": () => new Error("boom") }),
    {
      rootServers: ["10.0.0.1", "10.0.0.2", ROOT],
    },
  );

  const result = await resolver.resolve("example.com");
  assert.equal(result.addresses[0].address, "93.184.215.14");
  assert.deepEqual(client.calls.slice(0, 3), [
    "10.0.0.1 example.com",
    "10.0.0.2 example.com",
    `${ROOT} example.com`,
  ]);
});

test("tries the next glued name server when the first is lame", async () => {
  const servers = standardHierarchy({
    [COM]: () => ({
      authorities: [
        NS("example.com", "ns1.example.com"),
        NS("example.com", "ns2.example.com"),
      ],
      additionals: [
        A("ns1.example.com", "10.9.9.9"),
        A("ns2.example.com", EXAMPLE_NS),
      ],
    }),
    "10.9.9.9": () => ({ answers: [] }), // lame: no answer, no referral, not AA
  });
  const { resolver } = makeResolver(servers);

  assert.equal(
    (await resolver.resolve("example.com")).addresses[0].address,
    "93.184.215.14",
  );
});

test("resolves name servers independently when glue is missing", async () => {
  const servers = standardHierarchy({
    [COM]: (domain) =>
      domain === "example.com"
        ? { authorities: [NS("example.com", "ns.example.net")] } // no glue
        : new Error("unexpected"),
    [NET]: () => ({
      authorities: [NS("example.net", "ns.example.net")],
      additionals: [A("ns.example.net", "198.51.100.53")],
    }),
    "198.51.100.53": (domain) =>
      domain === "ns.example.net"
        ? authoritative([A("ns.example.net", "198.51.100.53")])
        : authoritative([A("example.com", "93.184.215.14", 120)]),
  });
  const { resolver, client } = makeResolver(servers);

  const result = await resolver.resolve("example.com");
  assert.equal(result.addresses[0].address, "93.184.215.14");
  assert.ok(client.calls.includes(`${ROOT} ns.example.net`));
  assert.equal(client.calls.at(-1), "198.51.100.53 example.com");
});

test("unglued name servers are only resolved if the glued ones fail", async () => {
  const servers = standardHierarchy({
    [COM]: () => ({
      authorities: [
        NS("example.com", "ns.example.com"),
        NS("example.com", "ns.other.net"),
      ],
      additionals: [A("ns.example.com", EXAMPLE_NS)],
    }),
  });
  const { resolver, client } = makeResolver(servers);

  await resolver.resolve("example.com");
  assert.ok(!client.calls.some((call) => call.endsWith("ns.other.net")));
});

test("ignores out-of-bailiwick glue and resolves the name server instead", async () => {
  const servers = standardHierarchy({
    [COM]: () => ({
      authorities: [NS("example.com", "ns.example.net")],
      additionals: [A("ns.example.net", "6.6.6.6")], // .com server can't vouch for .net
    }),
    "6.6.6.6": () => authoritative([A("example.com", "6.6.6.6")]),
    [NET]: () => ({
      authorities: [NS("example.net", "ns.example.net")],
      additionals: [A("ns.example.net", "198.51.100.53")],
    }),
    "198.51.100.53": (domain) =>
      domain === "ns.example.net"
        ? authoritative([A("ns.example.net", "198.51.100.53")])
        : authoritative([A("example.com", "93.184.215.14")]),
  });
  const { resolver, client } = makeResolver(servers);

  assert.equal(
    (await resolver.resolve("example.com")).addresses[0].address,
    "93.184.215.14",
  );
  assert.ok(!client.calls.some((call) => call.startsWith("6.6.6.6")));
});

test("follows a CNAME from the root and reports the chain", async () => {
  const servers = standardHierarchy({
    [EXAMPLE_NS]: (domain) =>
      domain === "www.example.com"
        ? authoritative([
            CNAME("www.example.com", "example.com", 60),
            A("example.com", "6.6.6.6"),
          ])
        : authoritative([A("example.com", "93.184.215.14", 120)]),
  });
  const { resolver, client } = makeResolver(servers);

  const result = await resolver.resolve("www.example.com");
  assert.equal(result.resolvedName, "example.com");
  assert.deepEqual(result.cnames, [
    { name: "www.example.com", target: "example.com", ttl: 60 },
  ]);
  assert.deepEqual(result.addresses, [{ address: "93.184.215.14", ttl: 120 }]);
  assert.equal(
    client.calls[3],
    `${ROOT} example.com`,
    "restarted at the root for the target",
  );
});

test("detects CNAME loops", async () => {
  const servers = standardHierarchy({
    [EXAMPLE_NS]: (domain) =>
      domain === "a.example.com"
        ? authoritative([CNAME("a.example.com", "b.example.com")])
        : authoritative([CNAME("b.example.com", "a.example.com")]),
  });
  const { resolver } = makeResolver(servers);

  await assert.rejects(resolver.resolve("a.example.com"), /alias loop/);
});

test("NXDOMAIN stops resolution with a clear error", async () => {
  const { resolver } = makeResolver(standardHierarchy());
  await assert.rejects(
    resolver.resolve("missing.example.com"),
    /does not exist: missing.example.com/,
  );
});

test("NODATA (authoritative, no A record) is reported, not retried forever", async () => {
  const servers = standardHierarchy({
    [EXAMPLE_NS]: () => ({
      flags: 0x8000 | AA,
      authorities: [NS("example.com", "ns.example.com")],
    }),
  });
  const { resolver, client } = makeResolver(servers);

  await assert.rejects(
    resolver.resolve("example.com"),
    /No A records for example.com/,
  );
  assert.equal(client.calls.length, 3);
});

test("upward referrals are ignored instead of looping", async () => {
  const servers = standardHierarchy({
    [EXAMPLE_NS]: () => ({
      authorities: [NS("com", "a.gtld-servers.net")],
      additionals: [A("a.gtld-servers.net", COM)],
    }),
  });
  const { resolver, client } = makeResolver(servers);

  await assert.rejects(
    resolver.resolve("example.com"),
    /No name server for example.com gave a usable answer/,
  );
  // The bogus referral back to .com is never followed.
  assert.equal(client.calls.filter((call) => call.startsWith(COM)).length, 1);
});

test("in-zone name servers with no glue fail fast", async () => {
  const servers = standardHierarchy({
    [COM]: () => ({ authorities: [NS("example.com", "ns1.example.com")] }),
  });
  const { resolver, client } = makeResolver(servers);

  await assert.rejects(resolver.resolve("example.com"), /no glue/);
  assert.equal(client.calls.length, 2);
});

test("query budget is enforced across nested name server lookups", async () => {
  // Every server refers to a zone whose name server lives under another
  // unglued zone, forever.
  let counter = 0;
  const servers = {
    // Delegate each TLD to an unglued name server under the *other* TLD.
    [ROOT]: (domain) => {
      const tld = domain.split(".").at(-1);
      const other = tld === "com" ? "net" : "com";
      counter++;
      return { authorities: [NS(tld, `ns${counter}.zone${counter}.${other}`)] };
    },
  };
  const { resolver, client } = makeResolver(servers, {
    maxQueries: 8,
    maxDepth: 100,
  });

  await assert.rejects(resolver.resolve("example.com"), /query count exceeded/);
  assert.equal(client.calls.length, 8);
});

test("maximum depth is enforced for nested name server lookups", async () => {
  let counter = 0;
  const servers = {
    // Delegate each TLD to an unglued name server under the *other* TLD.
    [ROOT]: (domain) => {
      const tld = domain.split(".").at(-1);
      const other = tld === "com" ? "net" : "com";
      counter++;
      return { authorities: [NS(tld, `ns${counter}.zone${counter}.${other}`)] };
    },
  };
  const { resolver } = makeResolver(servers, { maxQueries: 1000, maxDepth: 3 });

  await assert.rejects(resolver.resolve("example.com"), /depth exceeded/);
});

test("all servers failing gives a clear error", async () => {
  const { resolver } = makeResolver({ [ROOT]: () => new Error("timed out") });
  await assert.rejects(
    resolver.resolve("example.com"),
    /root zone gave a usable answer/,
  );
});

test("invalid names are rejected before any query", async () => {
  const { resolver, client } = makeResolver(standardHierarchy());
  await assert.rejects(resolver.resolve(""), /Invalid domain/);
  await assert.rejects(resolver.resolve("a..com"), /Invalid domain/);
  assert.equal(client.calls.length, 0);
});

test("answers are cached, TTLs count down, and entries expire", async () => {
  let now = 0;
  const { resolver, client } = makeResolver(standardHierarchy(), {
    cache: new DNSCache({ now: () => now }),
  });

  await resolver.resolve("example.com");
  const queriesAfterFirst = client.calls.length;

  now = 30_000;
  const cached = await resolver.resolve("EXAMPLE.com");
  assert.equal(
    client.calls.length,
    queriesAfterFirst,
    "no network on a cache hit",
  );
  assert.equal(cached.fromCache, true);
  assert.equal(cached.addresses[0].ttl, 90);

  now = 120_000;
  await resolver.resolve("example.com");
  assert.equal(
    client.calls.length,
    queriesAfterFirst * 2,
    "re-resolved after expiry",
  );
});

test("CNAME results are cached for the shortest TTL in the chain", async () => {
  let now = 0;
  const servers = standardHierarchy({
    [EXAMPLE_NS]: (domain) =>
      domain === "www.example.com"
        ? authoritative([CNAME("www.example.com", "example.com", 10)])
        : authoritative([A("example.com", "93.184.215.14", 120)]),
  });
  const cache = new DNSCache({ now: () => now });
  const { resolver } = makeResolver(servers, { cache });

  await resolver.resolve("www.example.com");
  now = 11_000;
  assert.equal(cache.get("www.example.com/A"), null);
  assert.notEqual(
    cache.get("example.com/A"),
    null,
    "the target keeps its own TTL",
  );
});

test("zero-TTL answers are returned but not cached", async () => {
  const servers = standardHierarchy({
    [EXAMPLE_NS]: () => authoritative([A("example.com", "93.184.215.14", 0)]),
  });
  const { resolver } = makeResolver(servers);

  await resolver.resolve("example.com");
  assert.equal(resolver.cache.size, 0);
});
