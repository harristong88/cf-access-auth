import { Accounts } from '../examples/express/accounts.js';
const accounts=new Accounts(process.argv[2]);
accounts.resolve({issuer:'https://fixture.cloudflareaccess.com',subject:'same-person',email:'alice@example.com',expiresAt:4102444800});
accounts.close();
