/**
 * Encode a domain name as DNS labels (RFC 1035 §3.1).
 * Accepts an optional trailing dot; "" or "." is the root name.
 */
export function encodeDomainName(domain) {
  const name = domain.endsWith(".") ? domain.slice(0, -1) : domain;

  if (name === "") {
    return Buffer.from([0]);
  }

  const parts = [];

  for (const label of name.split(".")) {
    if (label.length === 0) {
      throw new Error(`DNS name contains an empty label: ${domain}`);
    }

    // Printable ASCII only; internationalized names must be converted to
    // punycode (xn--...) first, otherwise Buffer.from(..., "ascii") mangles them.
    if (!/^[\x21-\x7e]+$/.test(label)) {
      throw new Error(`DNS label must be printable ASCII: ${label}`);
    }

    const encodedLabel = Buffer.from(label, "ascii");

    if (encodedLabel.length > 63) {
      throw new Error("DNS label exceeds 63 bytes");
    }

    const length = Buffer.from([encodedLabel.length]);

    parts.push(length, encodedLabel);
  }

  parts.push(Buffer.from([0]));

  const result = Buffer.concat(parts);

  if (result.length > 255) {
    throw new Error("DNS domain name exceeds 255 bytes");
  }

  return result;
}
