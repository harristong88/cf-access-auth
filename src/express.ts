import type { RequestHandler } from 'express';
import { AccessError, createAccessVerifier, type AccessConfig, type AccessIdentity } from './index.js';

declare global { namespace Express { interface Request { cfAccessIdentity?: AccessIdentity; cfAccessUser?: unknown } } }
export interface MiddlewareConfig<User> extends AccessConfig { resolveUser?: (identity: AccessIdentity) => User | Promise<User> }
export function cfAccessMiddleware<User>(config: MiddlewareConfig<User>): RequestHandler {
  const verifier = createAccessVerifier({...config, onDiagnostic: undefined});
  return async (req, res, next) => {
    try {
      // Node's normalized headers may merge duplicates; rawHeaders preserves their count.
      let count = 0;
      for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === 'cf-access-jwt-assertion') count++;
      if (count !== 1) throw new AccessError('ASSERTION_HEADER');
      const identity = await verifier.authenticateRequest(req.headers);
      const user = config.resolveUser ? await config.resolveUser(identity) : undefined;
      if (config.resolveUser && !user) throw new AccessError('ACCOUNT_DENIED', 403);
      req.cfAccessIdentity = identity;
      req.cfAccessUser = user;
      res.setHeader('Cache-Control', 'no-store');
      next();
    } catch (error) {
      if (!(error instanceof AccessError)) return next(error);
      try { config.onDiagnostic?.({code: error.code, status: error.status}); } catch { /* Logging cannot change authentication. */ }
      res.setHeader('Cache-Control', 'no-store');
      res.status(error.status).json({error: error.message});
    }
  };
}
