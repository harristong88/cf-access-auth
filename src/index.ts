import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';

export interface AccessIdentity { issuer: string; subject: string; email: string; expiresAt: number }
export type Diagnostic = (event: { code: string; status: number }) => void;
export class AccessError extends Error {
  constructor(public readonly code: string, public readonly status: 401 | 403 | 503 = 401) {
    super(status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Authentication unavailable');
    this.name = 'AccessError';
  }
}
export interface AccessConfig {
  teamDomain: string; audience: string | readonly string[];
  cacheMaxAge?: number; timeoutDuration?: number; cooldownDuration?: number;
  onDiagnostic?: Diagnostic;
  /** Transport injection for tests or custom networking; endpoint remains fixed by teamDomain. */
  fetch?: typeof globalThis.fetch;
}
export type HeaderInput = Headers | Record<string, string | string[] | undefined>;
export const MAX_TOKEN_BYTES = 16384;
export function normalizeEmail(email: string): string { return email.trim().toLowerCase(); }
export function assertionFromHeaders(headers: HeaderInput): string {
  const values: unknown[] = [];
  if (headers instanceof Headers) {
    const value = headers.get('cf-access-jwt-assertion');
    if (value !== null) values.push(value);
  } else {
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === 'cf-access-jwt-assertion' && value !== undefined) values.push(value);
    }
  }
  if (values.length !== 1 || typeof values[0] !== 'string') throw new AccessError('ASSERTION_HEADER');
  return validateToken(values[0]);
}
function validateToken(token: unknown): string {
  if (typeof token !== 'string' || Buffer.byteLength(token) > MAX_TOKEN_BYTES ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new AccessError('MALFORMED_TOKEN');
  return token;
}
export function createAccessVerifier(config: AccessConfig) {
  const url = new URL(config.teamDomain);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash ||
      url.pathname !== '/' || !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(url.hostname)) {
    throw new TypeError('teamDomain must be an HTTPS Cloudflare Access team origin');
  }
  const issuer = url.origin;
  const audience = typeof config.audience === 'string' ? [config.audience] : [...config.audience];
  if (!audience.length || audience.some(a => typeof a !== 'string' || !a.trim() || a !== a.trim())) throw new TypeError('audience is required');
  const settings = {cacheMaxAge: config.cacheMaxAge ?? 600000, timeoutDuration: config.timeoutDuration ?? 5000, cooldownDuration: config.cooldownDuration ?? 30000};
  for (const value of Object.values(settings)) if (!Number.isFinite(value) || value < 0) throw new TypeError('Invalid JWKS timing');
  const keys = createRemoteJWKSet(new URL('/cdn-cgi/access/certs', issuer), {...settings, [customFetch]: config.fetch});
  function report(error: AccessError): never {
    try { config.onDiagnostic?.({code: error.code, status: error.status}); } catch { /* Diagnostics cannot change authentication. */ }
    throw error;
  }
  async function verifyToken(token: string): Promise<AccessIdentity> {
    try {
      validateToken(token);
      const { payload, protectedHeader } = await jwtVerify(token, keys, {
        algorithms: ['RS256'], issuer, audience, requiredClaims: ['iss', 'aud', 'exp', 'iat', 'nbf', 'sub', 'email', 'type'], clockTolerance: 0,
      });
      if (typeof protectedHeader.kid !== 'string' || !protectedHeader.kid || payload.type !== 'app' ||
          typeof payload.email !== 'string' || !payload.email.trim() || typeof payload.sub !== 'string' || !payload.sub.trim() ||
          !['exp', 'iat', 'nbf'].every(k => typeof payload[k] === 'number' && Number.isSafeInteger(payload[k])) ||
          (payload.iat as number) > Math.floor(Date.now() / 1000) || (payload.exp as number) <= (payload.iat as number)) {
        throw new AccessError('INVALID_CLAIMS');
      }
      return Object.freeze({ issuer, subject: payload.sub, email: payload.email.trim(), expiresAt: payload.exp! });
    } catch (error) {
      if (error instanceof AccessError) return report(error);
      const code = (error as {code?: string}).code;
      // Key lookup failures are invalid credentials. Transport/JWKS availability errors are retryable.
      const invalid = ['ERR_JWT_EXPIRED','ERR_JWT_CLAIM_VALIDATION_FAILED','ERR_JWS_SIGNATURE_VERIFICATION_FAILED','ERR_JOSE_ALG_NOT_ALLOWED','ERR_JWS_INVALID','ERR_JWT_INVALID','ERR_JWKS_NO_MATCHING_KEY','ERR_JOSE_NOT_SUPPORTED'];
      return report(new AccessError(invalid.includes(code ?? '') ? 'INVALID_TOKEN' : 'JWKS_UNAVAILABLE', invalid.includes(code ?? '') ? 401 : 503));
    }
  }
  return {
    verifyToken,
    async authenticateRequest(headers: HeaderInput): Promise<AccessIdentity> {
      let token: string;
      try { token = assertionFromHeaders(headers); } catch (error) { return report(error as AccessError); }
      return verifyToken(token);
    },
  };
}
