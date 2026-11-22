import { DNS_CLASSES, DNS_PORT, DNS_TYPES } from "../dns/constants.js";
import { parseDNSMessage } from "../dns/decoder/parseDNSMessage.js";
import { buildQuery } from "../dns/encoder/buildQuery.js";
import { sendDNSQueryTCP } from "../network/tcpClient.js";
import { sendDNSQuery } from "../network/udpClient.js";
import { normalizeDomain } from "./utils.js";

/**
 * Sends one non-recursive query to one server and validates the response.
 * Falls back to TCP when the UDP response is truncated.
 */
export class DNSClient {
  constructor({ port = DNS_PORT, timeout = 3000 } = {}) {
    this.port = port;
    this.timeout = timeout;
  }

  async query(domain, server, type = DNS_TYPES.A) {
    const { packet, id } = buildQuery(domain, type, false);
    const expected = { id, domain, type };

    let message = validateResponse(
      parseDNSMessage(await sendDNSQuery(packet, server, this.port, this.timeout)),
      expected,
    );

    if (message.truncated) {
      // The TCP answer gets exactly the same checks as the UDP one.
      message = validateResponse(
        parseDNSMessage(
          await sendDNSQueryTCP(packet, server, this.port, this.timeout),
        ),
        expected,
      );

      if (message.truncated) {
        throw new Error("DNS response over TCP is still truncated");
      }
    }

    if (message.responseCode !== 0 && message.responseCode !== 3) {
      throw new Error(`DNS server returned RCODE ${message.responseCode}`);
    }

    return message;
  }
}

/**
 * Check that a parsed message really answers the query we sent:
 * same transaction ID, QR set, and the same single question echoed back.
 */
export function validateResponse(message, { id, domain, type }) {
  if (message.id !== id) {
    throw new Error("DNS transaction ID mismatch");
  }

  if (!message.isResponse) {
    throw new Error("Received a DNS query instead of a response");
  }

  const [question] = message.questions;

  if (
    message.questions.length !== 1 ||
    normalizeDomain(question.name) !== normalizeDomain(domain) ||
    question.type !== type ||
    question.class !== DNS_CLASSES.IN
  ) {
    throw new Error("DNS response question does not match the query");
  }

  return message;
}
