import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createCipheriv, hkdfSync, createHash } from 'node:crypto';
import { importKey, decrypt, validateManifest, verifyFile, fetchBytes } from '../crypto.mjs';

const raw=randomBytes(32), accessKey='HMF1-'+raw.toString('base64url');
const file={id:'a'.repeat(64),name:{en:'Test firmware','zh-TW':'測試韌體'},downloadName:'test.hex',bytes:4,sha256:createHash('sha256').update('test').digest('hex')};
const catalog={version:1,projects:[{id:'test',name:{en:'Test project','zh-TW':'測試專案'},releases:[{version:'1.0',files:[file]}]}]};
function encrypt(context,plain) {
  const magic=Buffer.from([72,77,70,87,1]),iv=randomBytes(12),domain='Hypothesis-Magic/firmware/v1/';
  const key=Buffer.from(hkdfSync('sha256',raw,Buffer.from(domain),Buffer.from(context),32));
  const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.concat([magic,Buffer.from(domain+context)]));
  return Buffer.concat([magic,iv,cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
}
test('browser crypto decrypts publisher format and rejects tampering, substitution and unsafe manifest paths',async()=>{
  const key=await importKey(accessKey), bytes=encrypt('manifest',Buffer.from(JSON.stringify(catalog)));
  assert.deepEqual(validateManifest(JSON.parse(new TextDecoder().decode(await decrypt(key,'manifest',bytes)))),catalog);
  await assert.rejects(decrypt(key,'blob/'+file.id,bytes)); bytes[bytes.length-1]^=1; await assert.rejects(decrypt(key,'manifest',bytes));
  const unsafe=structuredClone(catalog);unsafe.projects[0].releases[0].files[0].id='../secret';assert.throws(()=>validateManifest(unsafe));
  await verifyFile(file,Buffer.from('test'));await assert.rejects(verifyFile(file,Buffer.from('bad!')));
});
test('UI only fetches manifest on unlock, obtains storage consent, supports lock/forget and lazy verified downloads',async()=>{
  const elements=new Map(),windows=new Map();let downloads=0,writes=0,consent=false,requests=[],tampered=false,holdBlob=false,releaseBlob;
  class Element {
    constructor(tag='div'){this.tag=tag;this.textContent='';this.children=[];this.listeners={};this.value='';this.hidden=false;this.disabled=false;this.dataset={};this.classList={toggle(){}};}
    addEventListener(type,handler){this.listeners[type]=handler;}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;}
    click(){if(this.tag==='a')downloads++;return this.listeners.click?.({});}
    remove(){}
  }
  const storage=new Map();
  globalThis.document={documentElement:{},body:new Element('body'),getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},querySelectorAll(){return[];},createElement(tag){return new Element(tag);}};
  globalThis.window={confirm:()=>consent,addEventListener:(name,fn)=>windows.set(name,fn)};
  globalThis.location=new URL('https://hypothesis-magic.github.io/firmware-downloads/');
  Object.defineProperty(globalThis,'navigator',{value:{language:'en'},configurable:true});globalThis.isSecureContext=true;
  globalThis.localStorage={getItem:k=>storage.get(k)||null,setItem(k,v){writes++;storage.set(k,v);},removeItem:k=>storage.delete(k)};
  const originalFetch=globalThis.fetch,originalTimeout=globalThis.setTimeout;
  globalThis.setTimeout=(fn,ms)=>{const timer=originalTimeout(fn,ms);timer.unref();return timer;};
  globalThis.fetch=async path=>{
    requests.push(path);
    if(path.endsWith('manifest.enc'))return new Response(encrypt('manifest',Buffer.from(JSON.stringify(catalog))));
    if(holdBlob)await new Promise(resolve=>{releaseBlob=resolve;});
    const bytes=encrypt('blob/'+file.id,Buffer.from('test'));if(tampered)bytes[bytes.length-1]^=1;return new Response(bytes);
  };
  const get=id=>document.getElementById(id);
  const wait=async()=>{for(let i=0;i<1000;i++){if(!get('unlock').disabled)return;await new Promise(r=>originalTimeout(r,2));}throw new Error('UI did not settle');};
  const enter=async key=>{get('access-key').value=key;get('unlock-form').listeners.submit({preventDefault(){}});await wait();};
  const findButton=node=>node.tag==='button'?node:node.children.map(findButton).find(Boolean);
  try {
    await import('../app.mjs');assert.equal(requests.length,0);assert.equal(writes,0);
    await enter('HMF1-'+randomBytes(32).toString('base64url'));assert(get('unlocked').hidden);assert.equal(writes,0);assert.equal(get('projects').children.length,0);
    requests=[];await enter(accessKey);assert(!get('unlocked').hidden);assert.deepEqual(requests,['./protected/manifest.enc']);assert.equal(get('access-key').value,'');assert.equal(writes,0);
    get('remember').click();assert.equal(writes,0);consent=true;get('remember').click();assert.equal(writes,1);assert.equal(storage.size,1);
    get('lock').click();assert(get('unlocked').hidden);assert.equal(get('projects').children.length,0);assert.equal(storage.size,1);
    get('use-saved').click();await wait();assert(!get('unlocked').hidden);
    await findButton(get('projects')).click();assert.equal(downloads,1);assert(requests.at(-1).endsWith(file.id+'.enc'));
    tampered=true;await findButton(get('projects')).click();assert.equal(downloads,1);assert.match(get('status').textContent,/integrity/);
    tampered=false;holdBlob=true;const pending=findButton(get('projects')).click();get('lock').click();releaseBlob();await pending;assert.equal(downloads,1);assert(get('unlocked').hidden);
    get('forget').click();assert.equal(storage.size,0);assert(get('unlocked').hidden);
    get('language').value='zh-TW';get('language').listeners.change();assert.equal(document.documentElement.lang,'zh-TW');
  } finally {globalThis.fetch=originalFetch;globalThis.setTimeout=originalTimeout;}
});
test('bounded fetch rejects oversized payloads and HTTP errors',async()=>{
  const original=globalThis.fetch;
  try{globalThis.fetch=async()=>new Response('too large');await assert.rejects(fetchBytes('./x',2));globalThis.fetch=async()=>new Response('',{status:404});await assert.rejects(fetchBytes('./x',10));}finally{globalThis.fetch=original;}
});
