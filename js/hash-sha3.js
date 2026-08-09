/*
 * HashSentinel — pure JavaScript SHA-3 (256-bit) implementation.
 * Web Crypto's SubtleCrypto does not expose SHA-3, so Keccak-f[1600]
 * is implemented directly using BigInt 64-bit lanes. Runs fully
 * client-side on an in-memory ArrayBuffer.
 */
(function (global) {
  const MASK64 = (1n << 64n) - 1n;

  function rotl64(x, n) {
    x &= MASK64;
    return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
  }

  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];

  const R = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
  ];

  function keccakF(state) {
    for (let round = 0; round < 24; round++) {
      // Theta
      const C = new Array(5);
      for (let x = 0; x < 5; x++) {
        C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      const D = new Array(5);
      for (let x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
      }
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + 5 * y] ^= D[x];
        }
      }

      // Rho + Pi
      const B = new Array(25).fill(0n);
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          const newX = y;
          const newY = (2 * x + 3 * y) % 5;
          B[newX + 5 * newY] = rotl64(state[x + 5 * y], R[x + 5 * y]);
        }
      }

      // Chi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
        }
      }

      // Iota
      state[0] ^= RC[round];
      for (let i = 0; i < 25; i++) state[i] &= MASK64;
    }
    return state;
  }

  function sha3_256(buffer) {
    const rateBytes = 136; // (1600 - 2*256) / 8
    const bytes = new Uint8Array(buffer);

    // Padding: SHA-3 uses domain separator 0x06, then pad10*1
    const padLen = rateBytes - (bytes.length % rateBytes);
    const padded = new Uint8Array(bytes.length + padLen);
    padded.set(bytes);
    padded[bytes.length] = 0x06;
    padded[padded.length - 1] |= 0x80;

    let state = new Array(25).fill(0n);

    for (let offset = 0; offset < padded.length; offset += rateBytes) {
      for (let i = 0; i < rateBytes / 8; i++) {
        let lane = 0n;
        for (let b = 7; b >= 0; b--) {
          lane = (lane << 8n) | BigInt(padded[offset + i * 8 + b]);
        }
        state[i] ^= lane;
        state[i] &= MASK64;
      }
      state = keccakF(state);
    }

    // Squeeze 256 bits (32 bytes) = first 4 lanes
    let out = '';
    for (let i = 0; i < 4; i++) {
      let lane = state[i];
      for (let b = 0; b < 8; b++) {
        const byte = Number(lane & 0xffn);
        out += byte.toString(16).padStart(2, '0');
        lane >>= 8n;
      }
    }
    return out;
  }

  global.HashSentinelSHA3 = sha3_256;
})(typeof window !== 'undefined' ? window : this);
