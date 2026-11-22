import { decodeDomainName } from "./decodeDomainName.js";

export function parseQuestion(packet, offset) {
  const decoded = decodeDomainName(packet, offset);

  offset = decoded.offset;

  if (offset + 4 > packet.length) {
    throw new Error("Incomplete DNS question");
  }

  const type = packet.readUInt16BE(offset);

  const classCode = packet.readUInt16BE(offset + 2);

  offset += 4;

  return {
    question: {
      name: decoded.name,
      type,
      class: classCode,
    },
    offset,
  };
}
