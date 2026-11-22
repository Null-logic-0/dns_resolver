#!/usr/bin/env node
import { DNSResolver } from "./resolver/dnsResolver.js";

const domain = process.argv[2];

if (!domain) {
  console.error("Usage: node src/index.js <domain>");
  process.exit(1);
}

const resolver = new DNSResolver();

try {
  const result = await resolver.resolve(domain);

  console.log("\nResolution completed:");
  console.dir(result, { depth: null });
} catch (error) {
  console.error("Resolution failed:", error.message);
  process.exitCode = 1;
}
