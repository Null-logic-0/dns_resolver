// Test helper: builds wire-format DNS responses (no name compression)
// so tests can feed real bytes through the parser and network code.
import { encodeDomainName } from "../../src/dns/encoder/encodeDomainName.js";
import { parseDNSMessage } from "../../src/dns/decoder/parseDNSMessage.js";
import { DNS_TYPES, DNS_CLASSES } from "../../src/dns/constants.js";

export const QR = 0x8000;
export const AA = 0x0400;
export const TC = 0x0200;

function u16(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value, 0);
  return buffer;
}

function u32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return buffer;
}

function encodeRData(record) {
  if (Array.isArray(record.data) || Buffer.isBuffer(record.data)) {
    return Buffer.from(record.data); // raw RDATA for malformed-record tests
  }

  switch (record.type) {
    case DNS_TYPES.A:
      return Buffer.from(record.data.split(".").map(Number));
    case DNS_TYPES.NS:
    case DNS_TYPES.CNAME:
      return encodeDomainName(record.data);
    case DNS_TYPES.AAAA:
      return Buffer.concat(
        record.data.split(":").map((group) => u16(parseInt(group, 16))),
      );
    default:
      return Buffer.from(record.data ?? []);
  }
}

export function encodeRecord(record) {
  const rdata = encodeRData(record);
  return Buffer.concat([
    encodeDomainName(record.name),
    u16(record.type),
    u16(record.class ?? DNS_CLASSES.IN),
    u32(record.ttl ?? 300),
    u16(rdata.length),
    rdata,
  ]);
}

/**
 * @param {{ id?: number, flags?: number, rcode?: number,
 *   question?: { name: string, type?: number } | null,
 *   answers?: object[], authorities?: object[], additionals?: object[] }} spec
 */
export function buildResponse({
  id = 0,
  flags = QR,
  rcode = 0,
  question = { name: "example.com", type: DNS_TYPES.A },
  answers = [],
  authorities = [],
  additionals = [],
} = {}) {
  const questions = question
    ? [
        Buffer.concat([
          encodeDomainName(question.name),
          u16(question.type ?? DNS_TYPES.A),
          u16(DNS_CLASSES.IN),
        ]),
      ]
    : [];

  return Buffer.concat([
    u16(id),
    u16(flags | rcode),
    u16(questions.length),
    u16(answers.length),
    u16(authorities.length),
    u16(additionals.length),
    ...questions,
    ...answers.map(encodeRecord),
    ...authorities.map(encodeRecord),
    ...additionals.map(encodeRecord),
  ]);
}

export const parsedResponse = (spec) => parseDNSMessage(buildResponse(spec));

export const A = (name, data, ttl = 300) => ({ name, type: DNS_TYPES.A, data, ttl });
export const NS = (name, data, ttl = 3600) => ({ name, type: DNS_TYPES.NS, data, ttl });
export const CNAME = (name, data, ttl = 300) => ({ name, type: DNS_TYPES.CNAME, data, ttl });
