import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, copyFileSync, existsSync, writeFileSync, readFileSync } from 'node:fs';
const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const target=resolve(process.env.FILEGATOR_ROOT ?? '.artifacts/filegator');
const run=(program,args,cwd=target,env=process.env)=>execFileSync(program,args,{cwd,env,stdio:'inherit'});
if(existsSync(target))throw new Error('Choose an empty FILEGATOR_ROOT; this script does not overwrite an existing installation');
mkdirSync(dirname(target),{recursive:true});
run('git',['clone','--depth','1','--branch','v7.16.5','https://github.com/filegator/filegator.git',target],repo);
const commit=execFileSync('git',['rev-parse','HEAD'],{cwd:target,encoding:'utf8'}).trim();
if(commit!=='967618f7dc4af195b449aebe7dc735675f4d6193')throw new Error('Unexpected FileGator release commit');
run('git',['apply','--check',resolve(repo,'patches/filegator-7.16.5.patch')]);
run('git',['apply',resolve(repo,'patches/filegator-7.16.5.patch')]);
// Install an archive, so a fixture nested beneath the source repo remains independent.
const archiveDirectory=resolve(repo,'.artifacts');
mkdirSync(archiveDirectory,{recursive:true});
run('composer',['archive','--format=zip','--dir='+archiveDirectory,'--file=cf-access-auth-php-0.1.0'],repo);
const metadata=JSON.parse(readFileSync(resolve(repo,'composer.json'),'utf8'));
const archivePackage={name:metadata.name,version:'0.1.0',type:'library',require:metadata.require,autoload:metadata.autoload,bin:metadata.bin,
  dist:{type:'zip',url:resolve(archiveDirectory,'cf-access-auth-php-0.1.0.zip')}};
run('composer',['config','repositories.cf-access',JSON.stringify({type:'package',package:archivePackage})]);
run('composer',['require','cf-access/auth:0.1.0','--no-interaction','--update-no-dev']);
run('npm',['ci','--legacy-peer-deps','--ignore-scripts'],target,{...process.env,CYPRESS_INSTALL_BINARY:'0'});
run('npm',['run','build'],target,{...process.env,NODE_OPTIONS:'--openssl-legacy-provider'});
mkdirSync(resolve(target,'private/cf-access-cache'),{recursive:true,mode:0o700});
copyFileSync(resolve(repo,'examples/filegator/configuration.php'),resolve(target,'cf-access-configuration.php'));
// Explicitly test-only JWKS transport. Bind this fixture server to localhost, never to a tunnel.
const phpString=value=>"'"+value.replaceAll('\\','\\\\').replaceAll("'","\\'")+"'";
const fixtureConfig=`<?php\n$config = require __DIR__ . '/cf-access-configuration.php';\n$config['services']['Filegator\\\\Services\\\\Auth\\\\AuthInterface']['config']['fetch'] = static fn () => json_decode(file_get_contents(${phpString(resolve(repo,'fixtures/tokens.json'))}), true)['jwks'];\nreturn $config;\n`;
writeFileSync(resolve(target,'configuration.php'),fixtureConfig);
console.log(`Fixture prepared at ${target}. See docs/testing.md for the localhost-only server command.`);
