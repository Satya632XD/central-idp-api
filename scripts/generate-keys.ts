import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import * as crypto from 'node:crypto';

async function main() {
  console.log('--- Generating RS256 RSA Key Pair for Central IdP ---');
  
  const { publicKey, privateKey } = await generateKeyPair('RS256', {
    modulusLength: 2048,
    extractable: true,
  });

  const privateKeyPem = await exportPKCS8(privateKey);
  const publicKeyPem = await exportSPKI(publicKey);
  const encryptionKey = crypto.randomBytes(32).toString('hex');
  const adminApiKey = crypto.randomBytes(32).toString('hex');
  const jwtKeyId = `kid_${crypto.randomBytes(8).toString('hex')}`;

  console.log('\n=== GENERATED SECRETS FOR .env ===\n');
  console.log(`# Copy and paste these into your .env file:\n`);
  console.log(`JWT_KEY_ID="${jwtKeyId}"\n`);
  console.log(`JWT_PRIVATE_KEY="${privateKeyPem.replace(/\n/g, '\\n')}"\n`);
  console.log(`JWT_PUBLIC_KEY="${publicKeyPem.replace(/\n/g, '\\n')}"\n`);
  console.log(`ENCRYPTION_KEY="${encryptionKey}"\n`);
  console.log(`ADMIN_API_KEY="${adminApiKey}"\n`);
  console.log('===================================\n');
  console.log('IMPORTANT: Never commit private keys or encryption keys to version control!');
}

main().catch((err) => {
  console.error('Error generating keys:', err);
  process.exit(1);
});
