// One UUID per unconfirmed logical submission; only hashes/UUIDs enter storage.
(() => {
  const pending = new Map(), keys = new Map();
  function supports(path, options) {
    return (options.method || "GET").toUpperCase() === "POST" && typeof options.body === "string" &&
      (/^\/api\/(publish|account-actions|comment-rules|collections|dm\/auto-reply-rules)$/.test(path) ||
       /^\/api\/contents\/\d+\/repost-(xhs|douyin|shipinhao)$/.test(path));
  }
  // crypto.subtle only exists in Secure Contexts (HTTPS / localhost). LAN
  // deployments served over plain http://<vm-ip> have no subtle, so fall back
  // to a sync pure-JS SHA-256; the idempotency key only needs determinism.
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  function sha256Sync(data) {
    const rr = (x, n) => (x >>> n) | (x << (32 - n));
    const total = (((data.length + 8) >> 6) + 1) << 6;
    const buf = new Uint8Array(total);
    buf.set(data);
    buf[data.length] = 0x80;
    // Message sizes here are far below 4 GiB, so the high length word stays 0.
    new DataView(buf.buffer).setUint32(total - 4, (data.length * 8) >>> 0);
    const view = new DataView(buf.buffer);
    const w = new Uint32Array(64);
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2];
        const s0 = rr(x, 7) ^ rr(x, 18) ^ (x >>> 3);
        const s1 = rr(y, 17) ^ rr(y, 19) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3];
      let e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      const sum = [a, b, c, d, e, f, g, h];
      for (let i = 0; i < 8; i++) H[i] = (H[i] + sum[i]) >>> 0;
    }
    let hex = "";
    for (let i = 0; i < 8; i++) hex += H[i].toString(16).padStart(8, "0");
    return hex;
  }
  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, "0")).join("");
  }
  async function fingerprint(value) {
    if (globalThis.crypto?.subtle) {
      return toHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
    }
    return sha256Sync(new TextEncoder().encode(value));
  }
  function newKey() {
    return Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, "0")).join("");
  }
  window.CreatorHubSubmissions = {
    async run(path, options, send) {
      if (!supports(path, options)) return send(options);
      const signature = path + "\n" + options.body;
      if (pending.has(signature)) return pending.get(signature);
      const task = (async () => {
        const storageKey = "creatorhub-submission:" + await fingerprint(signature);
        let key = keys.get(storageKey);
        try { key = key || sessionStorage.getItem(storageKey); } catch (_) {}
        if (!key) key = newKey();
        keys.set(storageKey, key);
        try { sessionStorage.setItem(storageKey, key); } catch (_) {}
        const headers = new Headers(options.headers || {});
        if (!headers.has("Idempotency-Key")) headers.set("Idempotency-Key", key);
        const clear = () => {
          keys.delete(storageKey);
          try { sessionStorage.removeItem(storageKey); } catch (_) {}
        };
        try {
          // The caller parses JSON before success is confirmed. Truncated/lost
          // responses retain the key, just like network failures and HTTP 5xx.
          const result = await send({ ...options, headers });
          clear();
          return result;
        } catch (e) {
          if ([400, 404, 410, 413, 422].includes(e.status)) clear();
          throw e;
        }
      })();
      pending.set(signature, task);
      try { return await task; }
      finally { pending.delete(signature); }
    },
  };
})();
