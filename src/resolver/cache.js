export class DNSCache {
  /** @param {{ now?: () => number }} [options] - clock override for tests */
  constructor({ now = Date.now } = {}) {
    this.entries = new Map();
    this.now = now;
  }

  get(key) {
    return this.getWithAge(key)?.value ?? null;
  }

  /** Returns { value, age } where age is whole seconds since it was stored. */
  getWithAge(key) {
    const entry = this.entries.get(key);

    if (!entry) return null;

    const now = this.now();

    if (now >= entry.expiresAt) {
      this.entries.delete(key);

      return null;
    }

    return {
      value: entry.value,
      age: Math.floor((now - entry.storedAt) / 1000),
    };
  }

  set(key, value, ttl) {
    if (!(ttl > 0)) {
      return;
    }

    const now = this.now();

    this.entries.set(key, {
      value,
      storedAt: now,
      expiresAt: now + ttl * 1000,
    });
  }

  delete(key) {
    return this.entries.delete(key);
  }

  clear() {
    this.entries.clear();
  }

  get size() {
    return this.entries.size;
  }
}
