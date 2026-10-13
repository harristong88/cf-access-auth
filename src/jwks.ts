import { createRemoteJWKSet, customFetch, type JWTVerifyGetKey, type RemoteJWKSetOptions } from 'jose';
import { AccessError } from './access-error.js';

type KeySettings = Required<Pick<RemoteJWKSetOptions, 'cacheMaxAge' | 'timeoutDuration' | 'cooldownDuration'>>;

/** Private remote-key lookup, preserving fresh keys during download failure backoff. */
export function createKeyResolver(issuer: string, settings: KeySettings, fetch?: typeof globalThis.fetch): JWTVerifyGetKey {
  let retryAfter = 0;
  const transport = fetch ?? globalThis.fetch;
  const keys = createRemoteJWKSet(new URL('/cdn-cgi/access/certs', issuer), {
    ...settings,
    [customFetch]: async (url, options) => {
      // Only remote fetches are gated: fresh matching keys remain usable offline.
      if (performance.now() < retryAfter) throw new AccessError('JWKS_UNAVAILABLE', 503);
      return transport(url, options);
    },
  });
  const resolveKey: JWTVerifyGetKey = async (header, token) => {
    try { return await keys(header, token); }
    catch (error) {
      const code = (error as {code?: string})?.code;
      if (!(error instanceof AccessError) && code !== 'ERR_JWKS_NO_MATCHING_KEY' && code !== 'ERR_JOSE_NOT_SUPPORTED') {
        // jose's own cooldown covers successful downloads, but not failures.
        // Back off transport, HTTP, JSON and malformed-JWKS failures as well.
        retryAfter = performance.now() + settings.cooldownDuration;
      }
      throw error;
    }
  };
  return resolveKey;
}
