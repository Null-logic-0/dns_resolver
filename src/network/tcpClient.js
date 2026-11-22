import net from "node:net";

import { DNS_PORT } from "../dns/constants.js";

/**
 * Send a DNS query over TCP (RFC 1035 §4.2.2 / RFC 7766).
 * Each message is prefixed with its length as a 2-byte big-endian integer.
 *
 * @param {Buffer} packet - DNS query without the length prefix
 * @returns {Promise<Buffer>} DNS response without the length prefix
 */
export function sendDNSQueryTCP(
  packet,
  server,
  port = DNS_PORT,
  timeout = 5000,
) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: server, port });

    let buffer = Buffer.alloc(0);
    let settled = false;

    const finish = (error, response) => {
      if (settled) return;
      settled = true;

      socket.destroy();

      if (error) reject(error);
      else resolve(response);
    };

    socket.setTimeout(timeout, () =>
      finish(new Error(`DNS TCP query timed out: ${server}`)),
    );

    socket.on("error", (error) => finish(error));

    socket.on("connect", () => {
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(packet.length, 0);
      socket.write(Buffer.concat([prefix, packet]));
    });

    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      if (buffer.length < 2) return;

      const length = buffer.readUInt16BE(0);

      if (buffer.length < 2 + length) return;

      const response = buffer.subarray(2, 2 + length);

      if (response.length < 12) {
        finish(new Error("DNS TCP response is shorter than a DNS header"));
        return;
      }

      if (response.readUInt16BE(0) !== packet.readUInt16BE(0)) {
        finish(new Error("DNS TCP response ID mismatch"));
        return;
      }

      finish(null, response);
    });

    socket.on("end", () =>
      finish(new Error(`DNS TCP connection closed early: ${server}`)),
    );
  });
}
