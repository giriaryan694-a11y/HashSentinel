(function () {
  'use strict';

  /* ---------------- Theme ---------------- */
  const THEME_KEY = 'hashsentinel-theme';
  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
      themeIcon.textContent = '☀';
      document.querySelector('meta[name="theme-color"]').setAttribute('content', '#FBF6DF');
    } else {
      document.documentElement.removeAttribute('data-theme');
      themeIcon.textContent = '☾';
      document.querySelector('meta[name="theme-color"]').setAttribute('content', '#0B0F0E');
    }
  }

  const savedTheme = localStorage.getItem(THEME_KEY) ||
    (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  applyTheme(savedTheme);

  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });

  /* ---------------- Elements ---------------- */
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const fileName = document.getElementById('fileName');
  const fileMeta = document.getElementById('fileMeta');
  const clearFile = document.getElementById('clearFile');
  const progressTrack = document.getElementById('progressTrack');
  const progressFill = document.getElementById('progressFill');

  const algoSelect = document.getElementById('algoSelect');
  const collisionWarning = document.getElementById('collisionWarning');
  const collisionText = document.getElementById('collisionText');
  const expectedHash = document.getElementById('expectedHash');
  const verifyBtn = document.getElementById('verifyBtn');

  const resultSection = document.getElementById('resultSection');
  const seal = document.getElementById('seal');
  const resultStatus = document.getElementById('resultStatus');
  const resultSub = document.getElementById('resultSub');
  const computedHashEl = document.getElementById('computedHash');
  const expectedHashEcho = document.getElementById('expectedHashEcho');
  const toast = document.getElementById('toast');

  let currentFile = null;
  let toastTimer = null;

  const COLLISION_MESSAGES = {
    'MD5': 'MD5 has been practically broken since 2004. Attackers can craft two different files that share the same MD5 digest (a chosen-prefix collision), so a match does not prove authenticity — only that the file wasn\u2019t accidentally corrupted.',
    'SHA-1': 'SHA-1 collisions have been publicly demonstrated (e.g. the 2017 "SHAttered" attack). Don\u2019t rely on a SHA-1 match to prove a file hasn\u2019t been tampered with by a motivated attacker.'
  };

  /* ---------------- Algorithm change ---------------- */
  function updateCollisionWarning() {
    const algo = algoSelect.value;
    if (COLLISION_MESSAGES[algo]) {
      collisionText.textContent = COLLISION_MESSAGES[algo];
      collisionWarning.classList.remove('hidden');
    } else {
      collisionWarning.classList.add('hidden');
    }
  }
  algoSelect.addEventListener('change', () => {
    updateCollisionWarning();
    resetResult();
  });
  updateCollisionWarning();

  /* ---------------- File selection ---------------- */
  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
  }

  function setFile(file) {
    if (!file) return;
    currentFile = file;
    fileName.textContent = file.name;
    fileMeta.textContent = `${formatBytes(file.size)} \u00b7 ${file.type || 'unknown type'}`;
    fileInfo.classList.remove('hidden');
    verifyBtn.disabled = false;
    resetResult();
  }

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) setFile(e.target.files[0]);
  });

  ['dragenter', 'dragover'].forEach(evt => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(evt => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('drag-over');
    });
  });
  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files[0]) setFile(dt.files[0]);
  });

  clearFile.addEventListener('click', (e) => {
    e.stopPropagation();
    currentFile = null;
    fileInput.value = '';
    fileInfo.classList.add('hidden');
    verifyBtn.disabled = true;
    resetResult();
  });

  /* ---------------- Hashing ---------------- */
  function readFileAsArrayBuffer(file, onProgress) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onprogress = (e) => {
        if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
      };
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error('Could not read file'));
      reader.readAsArrayBuffer(file);
    });
  }

  function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function computeHash(algo, buffer) {
    if (algo === 'MD5') return window.HashSentinelMD5(buffer);
    if (algo === 'SHA3-256') return window.HashSentinelSHA3(buffer);
    // SubtleCrypto handles SHA-1 / SHA-256 / SHA-512 natively
    const digest = await crypto.subtle.digest(algo, buffer);
    return bufferToHex(digest);
  }

  /* ---------------- Result seal (signature element) ---------------- */
  // Renders a small ring of ticks generated from the hash's own bytes,
  // so every result's seal is visually unique to the digest it represents.
  function renderSeal(state, hashHex) {
    seal.className = 'seal ' + state;
    seal.innerHTML = '';

    if (state === 'pending') {
      seal.textContent = '\u22EF';
      return;
    }

    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', '0 0 100 100');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');

    const color = state === 'match' ? 'var(--mint)' : 'var(--danger)';
    const bytes = hashHex ? hashHex.match(/.{1,2}/g).slice(0, 32) : [];
    const count = Math.max(bytes.length, 16);

    for (let i = 0; i < count; i++) {
      const byte = bytes.length ? parseInt(bytes[i % bytes.length], 16) : 128;
      const angle = (i / count) * Math.PI * 2 - Math.PI / 2;
      const inner = 30 + (byte % 8);
      const outer = 44;
      const x1 = 50 + Math.cos(angle) * inner;
      const y1 = 50 + Math.sin(angle) * inner;
      const x2 = 50 + Math.cos(angle) * outer;
      const y2 = 50 + Math.sin(angle) * outer;
      const line = document.createElementNS(svgNS, 'line');
      line.setAttribute('x1', x1.toFixed(1));
      line.setAttribute('y1', y1.toFixed(1));
      line.setAttribute('x2', x2.toFixed(1));
      line.setAttribute('y2', y2.toFixed(1));
      line.setAttribute('stroke', color);
      line.setAttribute('stroke-width', '1.6');
      line.setAttribute('stroke-linecap', 'round');
      line.setAttribute('opacity', (0.35 + (byte / 255) * 0.65).toFixed(2));
      svg.appendChild(line);
    }

    const glyph = document.createElementNS(svgNS, 'text');
    glyph.setAttribute('x', '50');
    glyph.setAttribute('y', '58');
    glyph.setAttribute('text-anchor', 'middle');
    glyph.setAttribute('font-size', '28');
    glyph.setAttribute('fill', color);
    glyph.textContent = state === 'match' ? '\u2713' : '\u2715';
    svg.appendChild(glyph);

    seal.appendChild(svg);
  }

  function resetResult() {
    resultSection.classList.add('hidden');
  }

  function normalizeHash(str) {
    return str.trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
  }

  expectedHash.addEventListener('input', () => {
    // allow re-verify after edits without forcing a page state reset
  });

  /* ---------------- Verify flow ---------------- */
  verifyBtn.addEventListener('click', async () => {
    if (!currentFile) return;
    const algo = algoSelect.value;
    const expected = normalizeHash(expectedHash.value);

    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Computing\u2026';
    progressTrack.classList.remove('hidden');
    progressFill.style.width = '5%';

    resultSection.classList.remove('hidden');
    renderSeal('pending', null);
    resultStatus.textContent = 'Computing digest\u2026';
    resultStatus.style.color = 'var(--cyan)';
    resultSub.textContent = `Hashing ${currentFile.name} with ${algo} entirely in-browser.`;
    computedHashEl.textContent = '\u2026';
    expectedHashEcho.textContent = expected || '(none provided)';

    try {
      const buffer = await readFileAsArrayBuffer(currentFile, (pct) => {
        progressFill.style.width = `${Math.round(pct * 60)}%`;
      });
      progressFill.style.width = '75%';

      // Yield to the UI thread so the progress bar/paint isn't blocked
      await new Promise(r => setTimeout(r, 20));

      const computed = await computeHash(algo, buffer);
      progressFill.style.width = '100%';

      computedHashEl.textContent = computed;

      if (!expected) {
        renderSeal('pending', computed);
        resultStatus.textContent = 'Digest ready';
        resultStatus.style.color = 'var(--text)';
        resultSub.textContent = 'No expected hash was entered, so nothing to compare against \u2014 here\u2019s the computed digest.';
      } else if (computed.toLowerCase() === expected) {
        renderSeal('match', computed);
        resultStatus.textContent = 'Match \u2014 integrity verified';
        resultStatus.style.color = 'var(--mint)';
        resultSub.textContent = 'The computed digest matches the expected hash exactly.';
      } else {
        renderSeal('mismatch', computed);
        resultStatus.textContent = 'Mismatch \u2014 do not trust this file';
        resultStatus.style.color = 'var(--danger)';
        resultSub.textContent = 'The computed digest does not match. The file may be corrupted, incomplete, or tampered with.';
      }
    } catch (err) {
      renderSeal('mismatch', null);
      resultStatus.textContent = 'Could not compute hash';
      resultStatus.style.color = 'var(--danger)';
      resultSub.textContent = (err && err.message) || 'An unexpected error occurred while reading the file.';
      computedHashEl.textContent = '\u2014';
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.textContent = 'Verify integrity';
      setTimeout(() => progressTrack.classList.add('hidden'), 600);
    }
  });

  /* ---------------- Copy to clipboard ---------------- */
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.getAttribute('data-target');
      const text = document.getElementById(targetId).textContent;
      if (!text || text === '\u2014') return;
      try {
        await navigator.clipboard.writeText(text);
        showToast('Hash copied to clipboard');
      } catch {
        showToast('Could not copy \u2014 select the text manually');
      }
    });
  });

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add('hidden'), 2200);
  }

  /* ---------------- PWA install prompt ---------------- */
  const installBtn = document.getElementById('installBtn');
  let deferredPrompt = null;

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.classList.remove('hidden');
  });

  installBtn.addEventListener('click', async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
    installBtn.classList.add('hidden');
  });

  window.addEventListener('appinstalled', () => {
    installBtn.classList.add('hidden');
    showToast('HashSentinel installed');
  });

  /* ---------------- Service worker ---------------- */
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('sw.js').catch(() => {
        // offline install is a progressive enhancement; ignore failures silently
      });
    });
  }
})();
