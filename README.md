# HashSentinel

A client-side, installable file integrity checker. Drop a file, pick an
algorithm, paste the hash you were given, and HashSentinel tells you if
it's a match — all computed locally in your browser sandbox. No upload,
no backend, no tracking.

**Live demo:** https://giriaryan694-a11y.github.io/HashSentinel/

## Features

- **Algorithms:** MD5, SHA-1, SHA-2 (SHA-256 / SHA-512), SHA-3 (SHA3-256)
- **Defaults to SHA-256** — the recommended choice for verifying downloads
- **Collision-attack warning** — selecting MD5 or SHA-1 shows an alert
  explaining that both are broken against deliberate collision attacks
  and shouldn't be trusted to prove a file wasn't tampered with
- **Fully client-side** — uses the browser's native `SubtleCrypto` for
  SHA-1/256/512, plus small pure-JavaScript implementations of MD5 and
  SHA-3 (Web Crypto doesn't expose either), so nothing ever leaves the tab
- **Drag-and-drop or tap-to-browse** file selection, with progress feedback
  for large files
- **Installable PWA** — works fully offline once installed, on desktop
  and mobile
- **Dark mode by default**, with a warm "eye-saver" yellowish light theme
- **Responsive** from small phones up to wide desktop layouts

## How it works

1. Select a file (drag-and-drop, or click the drop zone to browse). The
   file is read locally with the `FileReader` API — it is never uploaded
   anywhere.
2. Choose a hash algorithm. SHA-256 is selected by default; MD5 and SHA-1
   show a collision-attack warning.
3. Paste the expected hash value (from a download page, checksum file,
   etc).
4. Click **Verify integrity**. HashSentinel computes the digest in-browser
   and shows a match / mismatch seal along with both hash values.

## Tech notes

- SHA-1, SHA-256 and SHA-512 use the browser's native
  `crypto.subtle.digest()` (Web Crypto API).
- MD5 and SHA-3 are **not** available in Web Crypto, so HashSentinel ships
  small, dependency-free implementations (`js/hash-md5.js`,
  `js/hash-sha3.js`) that operate purely on the in-memory `ArrayBuffer` —
  verified against known test vectors (MD5("") / MD5("abc"),
  SHA3-256("") / SHA3-256("abc")).
- No external JS dependencies. No analytics, no cookies, no fonts loaded
  from anywhere except Google Fonts for typography (optional — the app
  still works if that request is blocked).
- Service worker (`sw.js`) caches the full app shell (HTML/CSS/JS/icons)
  so the tool keeps working completely offline after first load.

## Project structure

```
HashSentinel/
├── index.html              # App shell / markup
├── manifest.json           # PWA manifest (icons, theme color, display mode)
├── sw.js                   # Service worker — offline app-shell caching
├── README.md
├── css/
│   └── style.css           # All styling (dark + eye-saver light theme)
├── js/
│   ├── script.js           # App logic: file intake, verify flow, UI, PWA install
│   ├── hash-md5.js         # Pure-JS MD5 (Web Crypto has no MD5)
│   └── hash-sha3.js        # Pure-JS SHA3-256 / Keccak (Web Crypto has no SHA-3)
└── icons/
    ├── icon.svg            # Source logo (hex seal / fingerprint mark)
    ├── icon-192.png
    ├── icon-512.png
    └── icon-180.png        # Apple touch icon
```

## Deploying to GitHub Pages

1. Push this folder to a GitHub repository (root of the repo, or a
   `/docs` folder — either works).
2. In the repo, go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to "Deploy from a
   branch", pick your branch (e.g. `main`) and the folder (`/root` or
   `/docs`).
4. Save. GitHub will publish the site at
   `https://<your-username>.github.io/<repo-name>/`.
5. All asset paths in this project are relative (`css/...`, `js/...`,
   `icons/...`), so it works correctly whether it's served from the
   domain root or a repo subpath — no changes needed.

## Try it now

No setup needed — it's already live on GitHub Pages:

**https://giriaryan694-a11y.github.io/HashSentinel/**

Open it, choose an algorithm, drop a file, and verify. You can install it
as a PWA straight from that page, and it'll keep working offline afterward.

## Security & privacy

- All hashing happens in-page, in memory, using the file you selected.
  HashSentinel makes no network requests with your file data — check the
  Network tab in DevTools if you want to verify this yourself.
- Because this is entirely static and client-side, you can audit the
  full source in this repository, or simply disconnect from the internet
  after the page loads and confirm it still works.

## License

MIT — do whatever you like with it, attribution appreciated but not required.

---

Made by **Aryan Giri** | [giriaryan694-a11y](https://github.com/giriaryan694-a11y)
