import express from 'express';
import { cfAccessMiddleware } from '../../src/express.js';
import { Accounts } from './accounts.js';

const teamDomain = process.env.CF_TEAM_DOMAIN;
const audience = process.env.CF_ACCESS_AUD;
if (!teamDomain || !audience) throw new Error('Set CF_TEAM_DOMAIN and CF_ACCESS_AUD');
const accounts = new Accounts(process.env.ACCOUNT_DB ?? 'accounts.sqlite', (process.env.CF_ADMIN_EMAILS ?? '').split(',').filter(Boolean));
const app = express();
app.disable('x-powered-by');
app.use(cfAccessMiddleware({teamDomain, audience: audience.split(','), resolveUser: identity => accounts.resolve(identity), onDiagnostic: event => console.warn(JSON.stringify(event))}));
app.get('/', (_req, res) => res.type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Access example</title><h1>Signed in through Cloudflare</h1><p>Your local account: <span id="user"></span></p><a href="/logout">Sign out of Cloudflare Access</a><script>fetch('/api/me').then(r=>r.json()).then(u=>document.querySelector('#user').textContent=u.email+' ('+u.role+')')</script></html>`));
app.get('/api/me', (req, res) => res.json(req.cfAccessUser));
// This example issues no local session/cookie. Existing apps must clear theirs before redirecting.
app.get('/logout', (_req, res) => res.redirect(303, '/cdn-cgi/access/logout'));
app.use((_req, res) => res.status(404).json({error: 'Not found'}));
app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Application request failed');
  res.status(503).json({error: 'Application unavailable'});
});
app.listen(Number(process.env.PORT ?? 3000), process.env.HOST ?? '127.0.0.1', () => console.log('Express example ready'));
