# Firmware downloads

[開啟下載頁 / Open downloads](https://hypothesis-magic.github.io/firmware-downloads/)

GitHub Pages 上的簡潔中英文韌體下載工具。完全靜態，vanilla JavaScript + Web Crypto，無 backend、第三方 JavaScript/CDN 或 runtime 套件。

## 使用 / Use

1. 輸入管理者提供的 Access Key。只有 encrypted manifest 成功解密後才會顯示專案與版本。
2. 點下載時才取得對應的 encrypted blob；AES-256-GCM 與 SHA-256 驗證成功後，瀏覽器才產生檔案下載。
3. 「記住這把 Access Key」會先詢問同意。預設只保留在頁面記憶體。**Lock** 清除當前狀態、取消下載；**Forget key and lock** 再移除 localStorage 中的 key。重新整理後，可手動選擇使用已記住的 key。

Enter an administrator-provided Access Key, then download a firmware file. Your key is never sent to GitHub. Files are fetched individually and decrypted in your browser. Remembering a key requires explicit confirmation; otherwise it stays in page memory only. Lock clears the current session; Forget also removes the saved key. HTTPS and a browser with Web Crypto are required.

## Repository and deployment

This public repository holds only site source and encrypted publication data. Firmware sources and their project/version metadata are maintained in a separate **private repository**. A fine-grained PAT limited to this repository with Contents read/write allows its Actions workflow to update only `protected/` through the publishing script. That push triggers this repository's GitHub Pages workflow. No custom Actions Secret belongs here.

```text
index.html / app.mjs / crypto.mjs / style.css
protected/
  manifest.enc
  <64-character opaque ID>.enc
```

Pages Settings → Source must be **GitHub Actions**. The workflow tests browser logic, copies an explicit allowlist into `_site/`, and deploys it using official Actions pinned to commits. README, tests, scripts, repository metadata and other files are excluded from the Pages artifact.

Local checks require Node.js 22+, no install:

```sh
node --test tests/*.test.mjs
node scripts/stage.mjs
python3 -m http.server 8080 --directory _site
```

Open `http://localhost:8080` (localhost is a secure context). `_site` must be absent before staging. Automated UI tests use a simulated DOM, not a visual or cross-browser test. Production firmware and keys must never appear in this repo, issues, commit messages or test fixtures.

## Encryption contract

Access keys use `HMF1-` followed by canonical base64url encoding of 32 cryptographically random bytes, without padding. Human-selected passwords are not supported. Envelopes contain `HMFW` + version byte `01` + 12-byte random IV + ciphertext + 16-byte GCM tag. Total overhead: 33 bytes.

Each AES-256 key is derived with HKDF-SHA-256, salt UTF-8 `Hypothesis-Magic/firmware/v1/`, info UTF-8 context `manifest` or `blob/<id>`. AAD is the five header bytes followed by UTF-8 `Hypothesis-Magic/firmware/v1/<context>`. Opaque IDs are keyed hashes of private path and content hash, not original filenames. Manifest names, versions, sizes and SHA-256 hashes are encrypted. Manifest plaintext is capped at 1 MiB; individual firmware at 64 MiB. Downloads are buffered in memory, so practical limits vary by device.

## Storage and security limits

GitHub project sites under `https://hypothesis-magic.github.io` share one origin. Storage is namespaced by path, but **other pages on that origin can still read localStorage**. The remember-key confirmation explains this; only use it on trusted devices and with trusted same-origin sites. A dedicated custom domain can provide origin isolation while keeping GitHub Pages hosting.

The HTML CSP blocks inline scripts/styles, third-party scripts/connections, forms and objects; all code is served locally. GitHub Pages does not provide custom HTTP headers, so this is a meta CSP. `frame-ancestors` cannot be enforced through a meta tag. CSP is defense in depth: anyone who can replace the public site code could steal an entered key, so protect repo write access and same-origin sites.

Ciphertext, sizes, counts and update timing are public. Key possession grants access to the whole catalog, not an individual identity. Holders can share keys/files and generate valid ciphertext. No server-side revocation, anti-replay protection or publisher digital signature is provided. Key rotation protects future publications; old public Git history remains decryptable with the old key. Lock cannot erase files already downloaded or guarantee immediate erasure of all JavaScript/browser memory.

References: [Web Crypto AES-GCM](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams), [GitHub Pages publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site), [deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys).
