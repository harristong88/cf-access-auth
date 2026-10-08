import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { AccessError, normalizeEmail, type AccessIdentity } from '../../src/index.js';

export interface LocalUser { id: string; email: string; role: string; disabled: number }
/** Example persistence only: adapt this transaction to your app's own user schema. */
export class Accounts {
  private db: DatabaseSync;
  private admins: Set<string>;
  constructor(path: string, adminEmails: string[] = []) {
    this.db = new DatabaseSync(path);
    this.admins = new Set(adminEmails.map(normalizeEmail));
    this.db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, role TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS bindings (issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL UNIQUE REFERENCES users(id), PRIMARY KEY(issuer,subject));`);
  }
  resolve(identity: AccessIdentity): LocalUser {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      let user = this.db.prepare('SELECT u.* FROM bindings b JOIN users u ON u.id=b.user_id WHERE b.issuer=? AND b.subject=?').get(identity.issuer, identity.subject) as unknown as LocalUser | undefined;
      if (!user) {
        const email = normalizeEmail(identity.email);
        user = this.db.prepare('SELECT * FROM users WHERE email=?').get(email) as unknown as LocalUser | undefined;
        if (user && this.db.prepare('SELECT 1 FROM bindings WHERE user_id=?').get(user.id)) throw new AccessError('RELINK_REQUIRED', 403);
        if (!user) {
          user = {id: randomUUID(), email, role: this.admins.has(email) ? 'admin' : 'user', disabled: 0};
          this.db.prepare('INSERT INTO users(id,email,role) VALUES(?,?,?)').run(user.id, user.email, user.role);
        }
        if (user.disabled) throw new AccessError('ACCOUNT_DISABLED', 403);
        this.db.prepare('INSERT INTO bindings VALUES(?,?,?)').run(identity.issuer, identity.subject, user.id);
      }
      if (user.disabled) throw new AccessError('ACCOUNT_DISABLED', 403);
      this.db.exec('COMMIT');
      return user;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  importUser(email: string, role = 'user'): void {
    if (!['user','admin'].includes(role)) throw new TypeError('Invalid role');
    this.db.prepare('INSERT INTO users VALUES(?,?,?,0)').run(randomUUID(), normalizeEmail(email), role);
  }
  disable(email: string): void { this.db.prepare('UPDATE users SET disabled=1 WHERE email=?').run(normalizeEmail(email)); }
  close(): void { this.db.close(); }
}
