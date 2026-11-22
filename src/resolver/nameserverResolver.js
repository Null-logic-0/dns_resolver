import { ResolutionLimitError } from "./utils.js";

export class NameServerResolver {
  constructor(resolveDomain, logger = console) {
    this.resolveDomain = resolveDomain;
    this.logger = logger;
  }

  /** Resolve name server hostnames to unique IPv4 addresses. */
  async resolve(nameservers, state) {
    const addresses = [];

    for (const nameserver of nameservers) {
      try {
        const result = await this.resolveDomain(nameserver, state);

        addresses.push(...result.addresses.map((item) => item.address));
      } catch (error) {
        if (error instanceof ResolutionLimitError) throw error;

        this.logger.error(`Could not resolve ${nameserver}: ${error.message}`);
      }
    }

    return [...new Set(addresses)];
  }
}
