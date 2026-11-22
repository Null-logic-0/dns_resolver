export function decodeDomainName(packet, startOffset) {
  const labels = [];

  let offset = startOffset;
  let nextOffset = null;

  const visited = new Set();

  // Wire length of the name so far (each label's length byte + bytes).
  let nameLength = 0;

  while (true) {
    if (offset >= packet.length) {
      throw new Error("DNS name exceeds packet boundaries");
    }

    const length = packet[offset];

    // Compression pointer
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length) {
        throw new Error("Incomplete DNS compression pointer");
      }

      const pointer = ((length & 0x3f) << 8) | packet[offset + 1];

      if (pointer >= packet.length) {
        throw new Error("Invalid DNS compression pointer");
      }

      if (nextOffset === null) {
        nextOffset = offset + 2;
      }

      if (visited.has(pointer)) {
        throw new Error("DNS compression pointer loop");
      }

      visited.add(pointer);

      offset = pointer;

      continue;
    }

    // Reserved label encodings
    if ((length & 0xc0) !== 0) {
      throw new Error("Unsupported DNS label encoding");
    }

    // End of domain name
    if (length === 0) {
      offset += 1;
      break;
    }
    const end = offset + 1 + length;

    if (end > packet.length) {
      throw new Error("DNS label exceeds packet boundaries");
    }

    nameLength += 1 + length;

    // +1 for the terminating zero byte (RFC 1035 §2.3.4: 255 octets max).
    if (nameLength + 1 > 255) {
      throw new Error("DNS name exceeds 255 bytes");
    }

    const label = packet.subarray(offset + 1, end).toString("ascii");

    labels.push(label);

    offset = end;
  }
  return {
    name: labels.join("."),
    offset: nextOffset ?? offset,
  };
}
