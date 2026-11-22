import { randomInt } from "node:crypto";

import { DNS_TYPES, DNS_CLASSES, DNS_FLAGS } from "../constants.js";
import { encodeDomainName } from "../encoder/encodeDomainName.js";

export function buildQuery(domain, type = DNS_TYPES.A, recursive = true) {
  const id = randomInt(0, 65536);

  const header = Buffer.alloc(12);

  header.writeUInt16BE(id, 0);

  const flags = recursive ? DNS_FLAGS.RD : 0;

  header.writeUInt16BE(flags, 2);

  header.writeUInt16BE(1, 4); // questions
  header.writeUInt16BE(0, 6); // answers
  header.writeUInt16BE(0, 8); // authorities
  header.writeUInt16BE(0, 10); // additionals

  const question = Buffer.alloc(4);

  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(DNS_CLASSES.IN, 2);

  const encodedName = encodeDomainName(domain);

  const packet = Buffer.concat([header, encodedName, question]);

  return {
    id,
    packet,
  };
}
