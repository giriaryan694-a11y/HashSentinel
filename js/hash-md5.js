/*
 * HashSentinel — pure JavaScript MD5 implementation.
 * Web Crypto's SubtleCrypto does not expose MD5, so a small in-browser
 * implementation is used instead. Operates entirely on an ArrayBuffer
 * already held in memory — nothing leaves the browser sandbox.
 */
(function (global) {
  function toWords(buffer) {
    const bytes = new Uint8Array(buffer);
    const bitLen = bytes.length * 8;

    // Pad: 0x80, then zeros, then 64-bit little-endian bit length,
    // total length a multiple of 64 bytes.
    let paddedLen = ((bytes.length + 8) >> 6 << 6) + 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(bytes);
    padded[bytes.length] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 8, bitLen >>> 0, true);
    view.setUint32(paddedLen - 4, Math.floor(bitLen / 0x100000000), true);

    const words = new Uint32Array(paddedLen / 4);
    for (let i = 0; i < words.length; i++) {
      words[i] = view.getUint32(i * 4, true);
    }
    return words;
  }

  function rotl(x, c) {
    return (x << c) | (x >>> (32 - c));
  }

  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];

  function md5(buffer) {
    const words = toWords(buffer);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (let chunk = 0; chunk < words.length; chunk += 16) {
      const M = words.subarray(chunk, chunk + 16);
      let A = a0, B = b0, C = c0, D = d0;

      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }

        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + rotl(F, S[i])) >>> 0;
      }

      a0 = (a0 + A) >>> 0;
      b0 = (b0 + B) >>> 0;
      c0 = (c0 + C) >>> 0;
      d0 = (d0 + D) >>> 0;
    }

    function toHexLE(n) {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, n, true);
      return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    }

    return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
  }

  global.HashSentinelMD5 = md5;
})(typeof window !== 'undefined' ? window : this);
