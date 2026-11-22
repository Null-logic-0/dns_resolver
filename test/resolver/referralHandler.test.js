import test from "node:test";
import assert from "node:assert/strict";

import { ReferralHandler } from "../../src/resolver/handler.js";
import { parsedResponse, A, NS } from "../helpers/dnsPacket.js";

const handler = new ReferralHandler();

test("extracts NS names and matching glue from a root referral", () => {
  const message = parsedResponse({
    authorities: [NS("com", "a.gtld-servers.net"), NS("com", "b.gtld-servers.net")],
    additionals: [A("a.gtld-servers.net", "192.5.6.30"), A("b.gtld-servers.net", "192.33.14.30")],
  });

  assert.deepEqual(handler.handle(message, "example.com", ""), {
    zone: "com",
    nameservers: ["a.gtld-servers.net", "b.gtld-servers.net"],
    glue: [
      { name: "a.gtld-servers.net", address: "192.5.6.30", ttl: 300 },
      { name: "b.gtld-servers.net", address: "192.33.14.30", ttl: 300 },
    ],
  });
});

test("picks the most specific delegation", () => {
  const message = parsedResponse({
    authorities: [NS("com", "a.gtld-servers.net"), NS("example.com", "ns1.example.com")],
  });
  assert.equal(handler.handle(message, "www.example.com", "").zone, "example.com");
});

test("ignores NS records unrelated to the queried name", () => {
  const message = parsedResponse({ authorities: [NS("example.org", "ns.example.org")] });
  assert.equal(handler.handle(message, "example.com", "com"), null);
});

test("ignores upward referrals (a .com server pointing back at the root)", () => {
  const message = parsedResponse({ authorities: [NS("", "a.root-servers.net")] });
  assert.equal(handler.handle(message, "example.com", "com"), null);
});

test("ignores referrals to the zone already being asked (no progress)", () => {
  const message = parsedResponse({ authorities: [NS("example.com", "ns1.example.com")] });
  assert.equal(handler.handle(message, "www.example.com", "example.com"), null);
});

test("matches names case-insensitively", () => {
  const message = parsedResponse({
    authorities: [NS("EXAMPLE.com", "NS1.Example.COM")],
    additionals: [A("ns1.example.com", "192.0.2.53")],
  });
  const referral = handler.handle(message, "www.Example.com", "com");
  assert.equal(referral.zone, "example.com");
  assert.deepEqual(referral.nameservers, ["ns1.example.com"]);
  assert.equal(referral.glue.length, 1);
});

test("drops Additional records that are not glue for the delegated servers", () => {
  const message = parsedResponse({
    authorities: [NS("example.com", "ns1.example.com")],
    additionals: [A("ns1.example.com", "192.0.2.53"), A("www.bank.com", "6.6.6.6")],
  });
  const referral = handler.handle(message, "example.com", "com");
  assert.deepEqual(referral.glue.map((g) => g.address), ["192.0.2.53"]);
});

test("drops glue outside the answering server's bailiwick", () => {
  // A .com server may not vouch for the address of a .net host.
  const message = parsedResponse({
    authorities: [NS("example.com", "ns.example.net")],
    additionals: [A("ns.example.net", "6.6.6.6")],
  });
  const referral = handler.handle(message, "example.com", "com");
  assert.deepEqual(referral.nameservers, ["ns.example.net"]);
  assert.deepEqual(referral.glue, []);
});
