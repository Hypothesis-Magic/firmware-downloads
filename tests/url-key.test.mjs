import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { consumeUrlKey } from '../url-key.mjs';

test('consume an encoded fragment key and clear current URL without putting the key in history state',()=>{
  const key='HMF1-'+randomBytes(32).toString('base64url');
  const location=new URL('https://example.test/downloads/?lang=en#key='+encodeURIComponent(key));
  let replacement;
  const history={state:null,replaceState(...args){replacement=args;}};
  assert.equal(consumeUrlKey(location,history),key);
  assert.deepEqual(replacement,[null,'','/downloads/?lang=en']);
});
test('invalid and duplicate fragment keys are removed before validation fails',()=>{
  for(const fragment of ['key=','key=bad','key=%ZZ','key=a&key=b']){
    let cleared=false;
    assert.throws(()=>consumeUrlKey(new URL('https://example.test/#'+fragment),{state:null,replaceState(){cleared=true;}}));
    assert(cleared);
  }
});
test('unrelated anchors and query parameters do not trigger unlock or history changes',()=>{
  for(const suffix of ['','#help','?key=example'])assert.equal(consumeUrlKey(new URL('https://example.test/'+suffix),{replaceState(){throw new Error('Unexpected history update');}}),null);
});
