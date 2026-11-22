# DNS Resolver

A small DNS resolver written from scratch in Node.js. You give it a domain name, like `google.com`, and it finds the IP address by asking the internet's DNS servers itself, one step at a time.

## Why I built this

Every time you open a website, your computer has to turn a name like `google.com` into an IP address. Usually some other service, like your router, Google's `8.8.8.8` or Cloudflare's `1.1.1.1`, does this for you, and you never see how it works.

I wanted to see what actually happens. So I built the whole thing by hand, with no DNS libraries:

- building DNS packets byte by byte
- sending them over UDP, and over TCP when the answer is too big
- reading the raw replies
- following the chain from the root servers down to the server that actually knows the answer

It's a learning project. It's not meant to replace a real resolver.

## How it works

DNS is like asking for directions:

1. **Ask a root server:** "Where is `google.com`?" It says: "I don't know, but ask the `.com` servers. Here they are."
2. **Ask a `.com` server.** It says: "Ask Google's own name servers. Here they are."
3. **Ask Google's name server.** It answers with the IP address.

That's called *iterative* resolution. This project does exactly those steps, and prints each one so you can watch.

It also handles the tricky cases:

- **Aliases (CNAME):** when one name points to another name
- **Missing addresses:** a server may name the next server without giving its IP address. The resolver then looks that address up on its own.
- **Failing servers:** if a server doesn't answer, it tries the next one
- **Answers too big for UDP:** it asks again over TCP
- **Bad or suspicious replies:** it ignores records a server has no authority to give
- **Limits:** it stops on loops and on lookups that take too many queries
- **Caching:** it remembers answers until their time-to-live (TTL) runs out

## How to use it

You need **Node.js 20 or newer**. There's nothing to install.

Look up a domain:

```bash
node src/index.js google.com
```

Example output:

```
Querying 198.41.0.4 (.) for google.com
Querying 192.5.6.30 (com) for google.com
Querying 216.239.34.10 (google.com) for google.com

Resolution completed:
{
  domain: 'google.com',
  resolvedName: 'google.com',
  cnames: [],
  addresses: [ { address: '142.250.185.78', ttl: 300 } ]
}
```

Each line shows which server was asked, which zone it's responsible for, and what name was asked about. The `ttl` is how many seconds the answer stays valid.

The exact servers and addresses will differ when you run it.

Run the tests:

```bash
npm test
```

The tests use fake DNS servers, so they work without internet access.

## Commands

| Command | What it does |
|---|---|
| `npm run resolve google.com` | Look up one domain (`npm start google.com` does the same) |
| `npm run demo` | Look up google.com, example.com, cloudflare.com and wikipedia.org |
| `npm test` | Run all tests |
| `npm run test:watch` | Re-run tests every time you save a file |
| `npm run test:coverage` | Run tests and show how much of the code they cover |
| `npm run test:unit` | Only the tests that don't use sockets (fast) |
| `npm run test:network` | Only the tests that use real local UDP/TCP sockets |

Want a `dns-resolve` command you can run anywhere? Run `npm link` once in this folder, then:

```bash
dns-resolve google.com
```

## Use it in your own code

```js
import { DNSResolver } from "./src/resolver/dnsResolver.js";

const resolver = new DNSResolver();
const result = await resolver.resolve("example.com");

console.log(result.addresses); // [{ address: "...", ttl: ... }]
```

## Project layout

```
src/
  index.js              command-line entry point
  dns/                  building and reading DNS packets (no networking)
  network/              sending packets over UDP and TCP
  resolver/
    dnsResolver.js      walks from the root down to the answer
    dnsClient.js        sends one query and checks the reply
    handler.js          reads "ask these servers next" replies
    nameserverResolver.js  looks up name servers' addresses when they're missing
    cache.js            remembers answers until they expire
test/                   automated tests with fake DNS servers
```

## What it doesn't do (yet)

- Only looks up IPv4 addresses (A records), not IPv6
- Only caches final answers, so each new name starts again at the root
- Doesn't remember "this name doesn't exist" answers
- No DNSSEC (it doesn't cryptographically verify answers)
- Asks one server at a time, so it's slower than a real resolver

## License

MIT. You can use, copy, change and share this code freely. See [LICENSE](LICENSE).
