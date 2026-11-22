export const DNS_PORT = 53;

export const DNS_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  AAAA: 28,
  OPT: 41,
};

export const DNS_CLASSES = {
  IN: 1,
};

export const DNS_FLAGS = {
  QR: 0x8000,
  AA: 0x400,
  TC: 0x0200,
  RD: 0x0100,
  RA: 0x0080,
};

export const DNS_RESPONSE_CODES = {
  NO_ERROR: 0,
  FORMAT_ERROR: 1,
  SERVER_FAILURE: 2,
  NAME_ERROR: 3,
  NOT_IMPLEMENTED: 4,
  REFUSED: 5,
};

// IPv4 addresses of a.root-servers.net … m.root-servers.net
export const ROOT_SERVERS = [
  "198.41.0.4", // a
  "170.247.170.2", // b
  "192.33.4.12", // c
  "199.7.91.13", // d
  "192.203.230.10", // e
  "192.5.5.241", // f
  "192.112.36.4", // g
  "198.97.190.53", // h
  "192.36.148.17", // i
  "192.58.128.30", // j
  "193.0.14.129", // k
  "199.7.83.42", // l
  "202.12.27.33", // m
];
