import { decodeDomainName } from "./decodeDomainName.js";

export function parseResourceRecord(packet, offset) {
  const decoded = decodeDomainName(packet, offset);

  const name = decoded.name;

  offset = decoded.offset;

  if (offset + 10 > packet.length) {
    throw new Error("Incomplete DNS resource record");
  }

  const type = packet.readUInt16BE(offset);
  const classCode = packet.readUInt16BE(offset + 2);

  // RFC 2181 §8: a TTL with the most significant bit set is treated as 0.
  const rawTTL = packet.readUInt32BE(offset + 4);
  const ttl = rawTTL > 0x7fffffff ? 0 : rawTTL;

  const dataLength = packet.readUInt16BE(offset + 8);

  offset += 10;

  const dataStart = offset;
  const dataEnd = dataStart + dataLength;

  if (dataEnd > packet.length) {
    throw new Error("DNS resource data exceeds packet boundaries");
  }

  let data;

  switch (type) {
    case 1: {
      if (dataLength !== 4) {
        throw new Error("Invalid IPv4 address record");
      }

      data = [...packet.subarray(dataStart, dataEnd)].join(".");
      break;
    }

    case 2:
    case 5: {
      const decodedData = decodeDomainName(packet, dataStart);

      // The name must fill RDATA exactly; anything else is malformed.
      if (decodedData.offset !== dataEnd) {
        throw new Error("Invalid compressed domain in RDATA");
      }

      data = decodedData.name;
      break;
    }

    case 28: {
      if (dataLength !== 16) {
        throw new Error("Invalid IPv6 address record");
      }

      const groups = [];

      for (let i = 0; i < 16; i += 2) {
        groups.push(packet.readUInt16BE(dataStart + i).toString(16));
      }

      data = groups.join(":");
      break;
    }

    default: {
      data = packet.subarray(dataStart, dataEnd);
    }
  }
  return {
    record: {
      name,
      type,
      class: classCode,
      ttl,
      data,
    },
    offset: dataEnd,
  };
}
