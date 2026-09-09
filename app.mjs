import { importKey, decrypt, fetchBytes, validateManifest, verifyFile } from './crypto.mjs';
const $ = id => document.getElementById(id);
const messages = {
  title:['韌體下載','Firmware downloads'], language:['語言','Language'], unlock:['解鎖','Unlock'], useSaved:['使用已記住的金鑰','Use saved key'], remember:['記住這把 Access Key','Remember this Access Key'], lock:['鎖定','Lock'], forget:['忘記金鑰並鎖定','Forget key and lock'], download:['下載','Download'], empty:['目前沒有可下載的韌體','No firmware is available yet.'], working:['正在解鎖…','Unlocking…'], failed:['無法解鎖，請確認金鑰、網路連線或檔案是否已發佈','Could not unlock. Check your key, connection, or publication status.'], downloadFailed:['下載失敗，或檔案完整性驗證未通過，請重新解鎖後再試','Download failed or integrity verification failed. Unlock again and retry.'], downloading:['正在下載與解密…','Downloading and decrypting…'], done:['檔案已驗證，已交給瀏覽器下載','File verified and handed to your browser for download.'], locked:['已鎖定','Locked.'], forgotten:['已移除這個瀏覽器儲存的金鑰，並鎖定','Saved key removed from this browser. Locked.'], saved:['此瀏覽器已記住金鑰','A key is saved in this browser.'], unsaved:['未在此瀏覽器記住金鑰','No key is saved in this browser.'], saveFailed:['瀏覽器不允許儲存金鑰','This browser did not allow key storage.'], removeFailed:['已鎖定，但無法移除儲存的金鑰，請清除此網站的瀏覽器資料','Locked, but the saved key could not be removed. Clear this site’s browser data.'], consent:['要將這把 Access Key 儲存在此瀏覽器嗎？使用這個瀏覽器的人，以及此 GitHub Pages 網域下的其他頁面，可能讀到金鑰，請只在你信任的私人裝置上記住','Save this Access Key in this browser? Anyone using this browser, and other pages on this GitHub Pages origin, may be able to read it. Only remember it on a trusted private device.'], unsupported:['需要支援 Web Crypto 的瀏覽器與 HTTPS','A browser with Web Crypto and HTTPS is required.']
};
let lang = navigator.language.startsWith('zh') ? 'zh-TW' : 'en';
// localStorage is origin-wide, so namespace by site path. This is not isolation from other same-origin pages.
const STORAGE = 'hmf-access-key:v1:' + new URL('.', location.href).pathname;
let key = null, keyText = '', manifest = null, generation = 0, controller = new AbortController(), busy = false, statusKey = '', statusError = false;
const urls = new Set();
const t = id => messages[id][lang === 'en' ? 1 : 0];
function status(id, error = false) { statusKey = id; statusError = error; $('status').textContent = id ? t(id) : ''; $('status').classList.toggle('error', error); }
function storageState() { let saved = false; try { saved = !!localStorage.getItem(STORAGE); } catch {} $('use-saved').hidden = !saved; $('forget').hidden = !saved; $('storage-state').textContent = t(saved ? 'saved' : 'unsaved'); }
function render() {
  document.documentElement.lang = lang; $('language').value = lang;
  document.querySelectorAll('[data-t]').forEach(el => { el.textContent = t(el.dataset.t); });
  $('locked').hidden = !!manifest; $('unlocked').hidden = !manifest;
  $('unlock').disabled = busy; $('use-saved').disabled = busy;
  $('projects').replaceChildren();
  if (manifest) {
    if (!manifest.projects.some(p => p.releases.some(r => r.files.length))) $('projects').append(element('p', t('empty')));
    for (const project of manifest.projects) {
      const section = element('section', '', 'project');
      for (const release of project.releases) {
        for (const file of release.files) {
          const row = element('div', '', 'file');
          row.append(
            element('h3', project.name[lang], 'file-project'),
            element('span', release.version, 'release'),
            element('span', file.downloadName, 'file-name'),
            element('span', new Intl.NumberFormat(lang).format(file.bytes) + ' bytes', 'file-size')
          );
          const button = element('button', t('download')); button.type = 'button'; button.disabled = busy; button.addEventListener('click', () => download(file));
          row.append(button); section.append(row);
        }
      }
      $('projects').append(section);
    }
  }
  storageState(); status(statusKey, statusError);
}
function element(tag, text, className) { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; }
function lock(message = 'locked') {
  generation++; controller.abort(); controller = new AbortController(); key = null; keyText = ''; manifest = null; busy = false; $('access-key').value = '';
  for (const url of urls) URL.revokeObjectURL(url); urls.clear();
  status(message); render();
}
async function unlock(value) {
  lock('working'); const current = generation; busy = true; render();
  try {
    const candidate = await importKey(value);
    const encrypted = await fetchBytes('./protected/manifest.enc', 1024 * 1024 + 33, controller.signal);
    const plain = await decrypt(candidate, 'manifest', encrypted);
    let next; try { next = validateManifest(JSON.parse(new TextDecoder('utf-8', { fatal:true }).decode(plain))); } finally { new Uint8Array(plain).fill(0); }
    if (current !== generation) return;
    key = candidate; keyText = value.trim(); manifest = next; status('');
  } catch { if (current === generation) status('failed', true); }
  finally { if (current === generation) { busy = false; render(); } }
}
async function download(file) {
  if (!key || busy) return;
  const current = generation, activeKey = key; busy = true; status('downloading'); render();
  let plain;
  try {
    const encrypted = await fetchBytes('./protected/' + file.id + '.enc', file.bytes + 33, controller.signal);
    plain = await decrypt(activeKey, 'blob/' + file.id, encrypted); await verifyFile(file, plain);
    if (current !== generation) return;
    const url = URL.createObjectURL(new Blob([plain], { type:'application/octet-stream' })); urls.add(url);
    const anchor = element('a', ''); anchor.href = url; anchor.download = file.downloadName; document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => { URL.revokeObjectURL(url); urls.delete(url); }, 60000); status('done');
  } catch { if (current === generation) status('downloadFailed', true); }
  finally { if (plain) new Uint8Array(plain).fill(0); if (current === generation) { busy = false; render(); } }
}
$('unlock-form').addEventListener('submit', event => { event.preventDefault(); if (!busy) void unlock($('access-key').value); });
$('use-saved').addEventListener('click', () => { try { const saved = localStorage.getItem(STORAGE); if (saved) void unlock(saved); } catch { status('saveFailed', true); } });
$('remember').addEventListener('click', () => { if (!keyText || !window.confirm(t('consent'))) return; try { localStorage.setItem(STORAGE, keyText); status('saved'); } catch { status('saveFailed', true); } storageState(); });
$('lock').addEventListener('click', () => lock());
$('forget').addEventListener('click', () => { let removed = true; try { localStorage.removeItem(STORAGE); } catch { removed = false; } lock(removed ? 'forgotten' : 'removeFailed'); if (!removed) status('removeFailed', true); });
$('language').addEventListener('change', () => { lang = $('language').value; render(); });
window.addEventListener('pagehide', () => lock());
window.addEventListener('storage', event => { if (event.key === STORAGE || event.key === null) { lock(); storageState(); } });
render();
if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) { busy = true; status('unsupported', true); render(); }
