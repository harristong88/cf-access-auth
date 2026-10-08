import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Accounts } from '../examples/express/accounts.js';
import { AccessError, type AccessIdentity } from '../src/index.js';
const identity: AccessIdentity = {issuer:'https://fixture.cloudflareaccess.com',subject:'s1',email:' Alice@Example.com ',expiresAt:4102444800};
test('provision once; admin bootstrap only for new users; disabled tombstone; subject changes',()=>{
  const accounts=new Accounts(':memory:',['alice@example.com']);
  const first=accounts.resolve(identity); assert.equal(first.role,'admin');
  assert.equal(accounts.resolve(identity).id,first.id);
  assert.throws(()=>accounts.resolve({...identity,subject:'s2'}),(e:AccessError)=>e.status===403);
  accounts.disable(identity.email); assert.throws(()=>accounts.resolve(identity),(e:AccessError)=>e.status===403);
  assert.throws(()=>accounts.resolve({...identity,subject:'s3'})); accounts.close();
});
test('email linking preserves existing user role and rejects duplicate normalized emails',()=>{
  const accounts=new Accounts(':memory:',['alice@example.com']); accounts.importUser(identity.email);
  assert.throws(()=>accounts.importUser('alice@example.com'));
  assert.equal(accounts.resolve(identity).role,'user'); accounts.close();
});
test('different people and issuers cannot take over an already-linked account',()=>{
  const accounts=new Accounts(':memory:'); const a=accounts.resolve(identity);
  const b=accounts.resolve({...identity,subject:'s2',email:'bob@example.com'}); assert.notEqual(a.id,b.id);
  assert.throws(()=>accounts.resolve({...identity,issuer:'https://other.cloudflareaccess.com'})); accounts.close();
});

test('concurrent first logins across processes create exactly one local account', async()=>{
  const {mkdtempSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {spawn}=await import('node:child_process');
  const directory=mkdtempSync(join(tmpdir(),'cf-access-node-'));const path=join(directory,'accounts.sqlite');
  try {
    await Promise.all(Array.from({length:6},()=>new Promise<void>((resolve,reject)=>{
      const child=spawn(process.execPath,['--experimental-sqlite','--import','tsx','test/accounts-worker.ts',path],{stdio:['ignore','pipe','pipe']});let error='';child.stderr.on('data',c=>error+=c);child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(new Error(error)));
    })));
    const {DatabaseSync}=await import('node:sqlite');const db=new DatabaseSync(path);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users').get()!.n,1);assert.equal(db.prepare('SELECT COUNT(*) AS n FROM bindings').get()!.n,1);db.close();
  } finally {rmSync(directory,{recursive:true,force:true});}
});
