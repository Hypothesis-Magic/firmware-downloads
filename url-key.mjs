import { parseKey } from './crypto.mjs';

export function consumeUrlKey(location, history) {
  const url = new URL(location.href);
  const params = new URLSearchParams(url.hash.slice(1));
  if (!params.has('key')) return null;
  // Remove even invalid keys before validating or making any download requests
  history.replaceState(history.state, '', url.pathname + url.search);
  const values = params.getAll('key');
  if (values.length !== 1) throw new Error('key');
  const value = values[0].trim();
  const raw = parseKey(value); raw.fill(0);
  return value;
}
