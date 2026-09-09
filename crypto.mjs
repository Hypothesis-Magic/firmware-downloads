const MAGIC = new Uint8Array([0x48, 0x4d, 0x46, 0x57, 1]);
const DOMAIN = 'Hypothesis-Magic/firmware/v1/';
const utf8 = new TextEncoder();
export function parseKey(text) {
  const value = text.trim();
  if (!/^HMF1-[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('key');
  const encoded = value.slice(5);
  const raw = Uint8Array.from(atob(encoded.replace(/-/g, '+').replace(/_/g, '/') + '='), c => c.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (raw.length !== 32 || encoded !== canonical) throw new Error('key');
  return raw;
}
export async function importKey(text) {
  const raw = parseKey(text);
  try { return await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']); }
  finally { raw.fill(0); }
}
export async function decrypt(master, context, envelope) {
  const bytes = new Uint8Array(envelope);
  if (bytes.length < 33 || !MAGIC.every((b, i) => bytes[i] === b)) throw new Error('format');
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: utf8.encode(DOMAIN), info: utf8.encode(context) }, master, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const contextBytes = utf8.encode(DOMAIN + context);
  const additionalData = new Uint8Array(MAGIC.length + contextBytes.length);
  additionalData.set(MAGIC); additionalData.set(contextBytes, MAGIC.length);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(5, 17), additionalData, tagLength: 128 }, key, bytes.slice(17));
}
export async function fetchBytes(path, maxBytes, signal) {
  const response = await fetch(path, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal });
  if (!response.ok) throw new Error('network');
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > maxBytes) throw new Error('size');
      chunks.push(value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
export function validateManifest(manifest) {
  const check = ok => { if (!ok) throw new Error('manifest'); };
  const label = value => check(value && ['en', 'zh-TW'].every(lang => typeof value[lang] === 'string' && value[lang].length > 0 && value[lang].length <= 500));
  check(manifest?.version === 1 && Array.isArray(manifest.projects));
  const ids = new Set();
  for (const project of manifest.projects) {
    check(typeof project.id === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(project.id));
    label(project.name); check(Array.isArray(project.releases));
    for (const release of project.releases) {
      check(typeof release.version === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(release.version));
      check(Array.isArray(release.files));
      for (const file of release.files) {
        check(/^[a-f0-9]{64}$/.test(file.id) && !ids.has(file.id)); ids.add(file.id);
        label(file.name);
        check(typeof file.downloadName === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._ -]{0,179}$/.test(file.downloadName) && /\.(hex|bin|uf2|zip)$/i.test(file.downloadName));
        check(Number.isSafeInteger(file.bytes) && file.bytes >= 0 && file.bytes <= 64 * 1024 * 1024);
        check(/^[a-f0-9]{64}$/.test(file.sha256));
      }
    }
  }
  return manifest;
}
export async function verifyFile(file, plain) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', plain));
  const hash = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
  if (plain.byteLength !== file.bytes || hash !== file.sha256) throw new Error('integrity');
}
