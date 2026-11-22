import { DNS_CLASSES, DNS_TYPES } from "../dns/constants.js";
import { findNSRecords, isSubdomain, normalizeDomain } from "./utils.js";

export class ReferralHandler {
  /**
   * Interpret the Authority/Additional sections of a response as a referral.
   *
   * @param {object} message - parsed DNS response
   * @param {string} domain - the name being resolved
   * @param {string} [currentZone] - zone the answering server was asked as
   *   authoritative for ("" = root). Used for bailiwick checks.
   * @returns {{ zone: string, nameservers: string[],
   *   glue: { name: string, address: string, ttl: number }[] } | null}
   */
  handle(message, domain, currentZone = "") {
    const zoneOfServer = normalizeDomain(currentZone);

    // Only accept delegations that move strictly *down* from the zone we
    // asked about, toward the queried name. Upward or sideways referrals
    // (e.g. a .com server claiming NS for "org" or for its own zone) are
    // ignored, so a lame or malicious server cannot send us in circles.
    const candidates = findNSRecords(message.authorities, domain).filter(
      (record) => {
        const zone = normalizeDomain(record.name);
        return zone !== zoneOfServer && isSubdomain(zone, zoneOfServer);
      },
    );

    if (candidates.length === 0) {
      return null;
    }

    const zones = candidates.map((record) => normalizeDomain(record.name));

    const bestZone = zones.reduce((best, zone) =>
      zone.length > best.length ? zone : best,
    );

    const nameservers = [
      ...new Set(
        candidates
          .filter((record) => normalizeDomain(record.name) === bestZone)
          .map((record) => normalizeDomain(record.data)),
      ),
    ];

    const nameserverNames = new Set(nameservers);

    // Glue must (a) belong to one of the delegated name servers and
    // (b) be inside the answering server's bailiwick. Anything else in the
    // Additional section is ignored (cache-poisoning protection).
    const glue = message.additionals.filter(
      (record) =>
        record.type === DNS_TYPES.A &&
        record.class === DNS_CLASSES.IN &&
        nameserverNames.has(normalizeDomain(record.name)) &&
        isSubdomain(record.name, zoneOfServer),
    );

    return {
      zone: bestZone,
      nameservers,
      glue: glue.map((record) => ({
        name: normalizeDomain(record.name),
        address: record.data,
        ttl: record.ttl,
      })),
    };
  }
}
