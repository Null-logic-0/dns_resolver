import { parseQuestion } from "./parseQuestion.js";
import { parseResourceRecord } from "./parseResourceRecord.js";

export function parseDNSMessage(packet) {
  if (packet.length < 12) {
    throw new Error("DNS packet is shorter than its header");
  }

  const id = packet.readUInt16BE(0);
  const flags = packet.readUInt16BE(2);

  const questionCount = packet.readUInt16BE(4);
  const answerCount = packet.readUInt16BE(6);
  const authorityCount = packet.readUInt16BE(8);
  const additionalCount = packet.readUInt16BE(10);

  let offset = 12;

  const questions = [];
  const answers = [];
  const authorities = [];
  const additionals = [];

  for (let i = 0; i < questionCount; i++) {
    const result = parseQuestion(packet, offset);
    questions.push(result.question);

    offset = result.offset;
  }

  const sections = [
    [answers, answerCount],
    [authorities, authorityCount],
    [additionals, additionalCount],
  ];

  for (const [records, count] of sections) {
    for (let i = 0; i < count; i++) {
      const result = parseResourceRecord(packet, offset);

      records.push(result.record);

      offset = result.offset;
    }
  }

  return {
    id,
    flags,

    isResponse: (flags & 0x8000) !== 0,
    authoritative: (flags & 0x0400) !== 0,
    truncated: (flags & 0x0200) !== 0,
    recursionDesired: (flags & 0x0100) !== 0,
    recursionAvailable: (flags & 0x0080) !== 0,

    responseCode: flags & 0x000f,

    questions,
    answers,
    authorities,
    additionals,
  };
}
