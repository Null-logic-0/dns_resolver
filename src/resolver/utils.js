import { DNS_CLASSES, DNS_TYPES } from "../dns/constants.js";

export function normalizeDomain(domain) {
  return domain.replace(/\.$/, "").toLowerCase();
}

/** True when `name` equals `zone` or is below it. The root zone is "". */
export function isSubdomain(name, zone) {
  const normalizedName = normalizeDomain(name);
  const normalizedZone = normalizeDomain(zone);

  return (
    normalizedZone === "" ||
    normalizedName === normalizedZone ||
    normalizedName.endsWith(`.${normalizedZone}`)
  );
}

export function findARecords(records, domain) {
  const normalized = normalizeDomain(domain);

  return records.filter(
    (record) =>
      record.type === DNS_TYPES.A &&
      record.class === DNS_CLASSES.IN &&
      normalizeDomain(record.name) === normalized,
  );
}

export function findCNAME(records, domain) {
  const normalized = normalizeDomain(domain);

  return records.find(
    (record) =>
      record.type === DNS_TYPES.CNAME &&
      normalizeDomain(record.name) === normalized,
  );
}

export function findNSRecords(records, domain) {
  const normalized = normalizeDomain(domain);

  return records.filter((record) => {
    if (record.type !== DNS_TYPES.NS) {
      return false;
    }

    const zone = normalizeDomain(record.name);

    return normalized === zone || normalized.endsWith(`.${zone}`);
  });
}

/**
 * Thrown when a global safety limit (query budget, recursion depth) is hit.
 * It must abort the whole resolution, not just one name server attempt.
 */
export class ResolutionLimitError extends Error {
  name = "ResolutionLimitError";
}
