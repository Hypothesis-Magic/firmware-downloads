import { mkdir, copyFile, readdir, lstat, readFile } from 'node:fs/promises';
import { join } from 'node:path';

// Explicit Pages artifact allowlist: no repository metadata, tests, docs or arbitrary extensions.
const output = process.argv[2] || '_site';
await mkdir(output, {recursive:false});
for (const name of ['index.html','app.mjs','crypto.mjs','style.css','.nojekyll']) await copyFile(name,join(output,name));
await mkdir(join(output,'protected'));
const names=await readdir('protected');
if(!names.includes('manifest.enc')) throw new Error('Missing encrypted manifest');
for(const name of names) {
  if(name !== 'manifest.enc' && !/^[a-f0-9]{64}\.enc$/.test(name)) throw new Error('Unexpected public data filename');
  const path=join('protected',name), info=await lstat(path);
  if(!info.isFile() || info.isSymbolicLink() || info.size<33 || info.size>64*1024*1024+33) throw new Error('Invalid encrypted file');
  const data=await readFile(path);
  if(!Buffer.from([72,77,70,87,1]).equals(data.subarray(0,5))) throw new Error('Invalid format');
  await copyFile(path,join(output,'protected',name));
}
console.log('Static Pages artifact staged from allowlisted files.');
