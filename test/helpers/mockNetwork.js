// A scripted DNS hierarchy for resolver tests. Each server IP maps to a
// function (domain) => response spec (see dnsPacket.buildResponse) or an
// Error to throw. The mock client returns *parsed wire bytes*, so the real
// parser runs on every response.
import { parsedResponse } from "./dnsPacket.js";

export function mockClient(servers) {
  const calls = [];

  return {
    calls,
    async query(domain, server) {
      calls.push(`${server} ${domain}`);
      const handler = servers[server];

      if (!handler) throw new Error(`timeout: ${server}`);

      const spec = handler(domain);

      if (spec instanceof Error) throw spec;

      return parsedResponse({ question: { name: domain }, ...spec });
    },
  };
}

export const silentLogger = { log() {}, error() {} };
