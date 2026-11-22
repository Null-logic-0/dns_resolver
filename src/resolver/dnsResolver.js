import { ROOT_SERVERS } from "../dns/constants.js";
import { DNSCache } from "./cache.js";
import { DNSClient } from "./dnsClient.js";
import { ReferralHandler } from "./handler.js";
import { NameServerResolver } from "./nameserverResolver.js";
import {
  findARecords,
  findCNAME,
  isSubdomain,
  normalizeDomain,
  ResolutionLimitError,
} from "./utils.js";

/** Coordinates iterative resolution of A records, starting at the root. */
export class DNSResolver {
  constructor({
    rootServers = ROOT_SERVERS,
    maxDepth = 10,
    maxQueries = 50,
    client = new DNSClient(),
    cache = new DNSCache(),
    logger = console,
  } = {}) {
    this.rootServers = rootServers;
    this.maxDepth = maxDepth;
    this.maxQueries = maxQueries;

    this.cache = cache;
    this.client = client;
    this.logger = logger;
    this.referralHandler = new ReferralHandler();

    this.nameserverResolver = new NameServerResolver(
      (domain, state) => this.resolve(domain, state),
      logger,
    );
  }

  /**
   * @param {string} domain
   * @param {{ depth?: number, budget?: { queries: number } }} [state]
   *   Internal recursion state for name server lookups; callers omit it.
   * @returns {Promise<{ domain: string, resolvedName: string,
   *   cnames: { name: string, target: string, ttl: number }[],
   *   addresses: { address: string, ttl: number }[], fromCache?: boolean }>}
   */
  async resolve(domain, state = {}) {
    const normalizedDomain = normalizeDomain(domain);

    if (!normalizedDomain || normalizedDomain.split(".").includes("")) {
      throw new Error("Invalid domain name");
    }

    const depth = state.depth ?? 0;
    const budget = state.budget ?? { queries: 0 };

    if (depth > this.maxDepth) {
      throw new ResolutionLimitError("Maximum DNS resolution depth exceeded");
    }

    const cacheKey = `${normalizedDomain}/A`;
    const cached = this.cache.getWithAge(cacheKey);

    if (cached) {
      return withAgedTTLs(cached.value, cached.age);
    }

    // Names seen along the CNAME chain (referrals keep the same name, so
    // only CNAME steps are checked against this).
    const visited = new Set([normalizedDomain]);
    const cnames = [];

    let currentDomain = normalizedDomain;
    let zone = "";
    let servers = [...this.rootServers];
    let pendingNames = [];

    while (true) {
      const step = await this.#askZone(currentDomain, zone, servers, pendingNames, {
        depth,
        budget,
      });

      if (step.kind === "answer") {
        const result = {
          domain: normalizedDomain,
          resolvedName: currentDomain,
          cnames,
          addresses: step.records.map((record) => ({
            address: record.data,
            ttl: record.ttl,
          })),
        };

        // Cache for the shortest TTL along the whole CNAME chain.
        const ttl = Math.min(
          ...cnames.map((cname) => cname.ttl),
          ...result.addresses.map((address) => address.ttl),
        );
        this.cache.set(cacheKey, structuredClone(result), ttl);

        // The CNAME target is also a fully resolved name; cache it on its own.
        if (cnames.length > 0) {
          this.cache.set(
            `${currentDomain}/A`,
            { ...result, domain: currentDomain, cnames: [] },
            Math.min(...result.addresses.map((address) => address.ttl)),
          );
        }

        return result;
      }

      if (step.kind === "cname") {
        const target = normalizeDomain(step.record.data);

        if (visited.has(target)) {
          throw new Error(`DNS alias loop detected: ${target}`);
        }

        visited.add(target);
        cnames.push({ name: currentDomain, target, ttl: step.record.ttl });

        // Restart from the root: an A record for the target supplied by the
        // server that owns the alias is out of its bailiwick, so don't trust it.
        currentDomain = target;
        zone = "";
        servers = [...this.rootServers];
        pendingNames = [];
        continue;
      }

      // Referral: descend one zone.
      const { referral } = step;

      zone = referral.zone;
      servers = [...new Set(referral.glue.map((glue) => glue.address))];

      const glueNames = new Set(referral.glue.map((glue) => glue.name));

      // Names without glue get resolved lazily, only if the glued servers
      // fail. Names inside the delegated zone can't be resolved without glue
      // (that would need the very servers we're looking for), so skip them.
      pendingNames = referral.nameservers.filter(
        (name) => !glueNames.has(name) && !isSubdomain(name, zone),
      );

      if (servers.length === 0 && pendingNames.length === 0) {
        throw new Error(
          `Referral to ${zone} has in-zone name servers but no glue records`,
        );
      }
    }
  }

  /**
   * Query the servers for one zone until one gives a usable answer.
   * Unglued name server names are resolved one at a time, only when needed.
   */
  async #askZone(domain, zone, servers, pendingNames, { depth, budget }) {
    const queue = [...servers];
    const pending = [...pendingNames];
    const tried = new Set();

    while (queue.length > 0 || pending.length > 0) {
      if (queue.length === 0) {
        const name = pending.shift();
        const addresses = await this.nameserverResolver.resolve([name], {
          depth: depth + 1,
          budget,
        });

        queue.push(...addresses.filter((address) => !tried.has(address)));
        continue;
      }

      const server = queue.shift();

      if (tried.has(server)) continue;
      tried.add(server);

      budget.queries++;

      if (budget.queries > this.maxQueries) {
        throw new ResolutionLimitError("Maximum DNS query count exceeded");
      }

      let message;

      try {
        this.logger.log(`Querying ${server} (${zone || "."}) for ${domain}`);
        message = await this.client.query(domain, server);
      } catch (error) {
        this.logger.error(`Failed querying ${server}: ${error.message}`);
        continue;
      }

      if (message.responseCode === 3) {
        throw new Error(`Domain does not exist: ${domain}`);
      }

      const records = findARecords(message.answers, domain);

      if (records.length > 0) {
        return { kind: "answer", records };
      }

      const cname = findCNAME(message.answers, domain);

      if (cname) {
        return { kind: "cname", record: cname };
      }

      const referral = this.referralHandler.handle(message, domain, zone);

      if (referral) {
        return { kind: "referral", referral };
      }

      if (message.authoritative) {
        // Authoritative, NOERROR, but no A record: the name exists without
        // an IPv4 address (NODATA).
        throw new Error(`No A records for ${domain}`);
      }

      this.logger.error(
        `Unusable response from ${server} for ${domain} (no answer, no valid referral)`,
      );
    }

    throw new Error(
      `No name server for ${zone || "the root zone"} gave a usable answer for ${domain}`,
    );
  }
}

function withAgedTTLs(result, age) {
  return {
    ...result,
    cnames: result.cnames.map((cname) => ({
      ...cname,
      ttl: Math.max(0, cname.ttl - age),
    })),
    addresses: result.addresses.map((address) => ({
      ...address,
      ttl: Math.max(0, address.ttl - age),
    })),
    fromCache: true,
  };
}
