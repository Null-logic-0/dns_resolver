import dgram from "node:dgram";

import { DNS_PORT } from "../dns/constants.js";

export function sendDNSQuery(packet, server, port = DNS_PORT, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");

    let settled = false;

    const finish = (error, response) => {
      if (settled) return;

      settled = true;

      clearTimeout(timer);
      socket.close();

      if (error) {
        reject(error);
      } else {
        resolve(response);
      }
    };

    const timer = setTimeout(() => {
      finish(new Error(`DNS query timed out: ${server}`));
    }, timeout);

    socket.on("error", (error) => finish(error));

    socket.on("message", (message, remote) => {
      // Ignore datagrams from anyone but the server we asked (spoofing).
      if (remote.address !== server || remote.port !== port) return;

      if (message.length < 12) return;

      const responseId = message.readUInt16BE(0);
      const requestId = packet.readUInt16BE(0);

      const flags = message.readUInt16BE(2);

      if (responseId !== requestId) return;

      if ((flags & 0x8000) === 0) return;

      finish(null, message);
    });

    socket.send(packet, port, server, (error) => {
      if (error) finish(error);
    });
  });
}
