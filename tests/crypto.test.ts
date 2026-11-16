import { CryptoService } from '../src/services/crypto.service.js';

async function runTest() {
  console.log('Testing CryptoService...');
  
  // Test Argon2id
  const password = 'SecurePassword123!';
  const hash = await CryptoService.hashPassword(password);
  const match = await CryptoService.verifyPassword(hash, password);
  const falseMatch = await CryptoService.verifyPassword(hash, 'WrongPassword');
  console.log('Argon2id Hash Match:', match === true && falseMatch === false ? 'PASS' : 'FAIL');

  // Test AES-256-GCM
  const secret = 'JBSWY3DPEHPK3PXP';
  const encrypted = CryptoService.encryptAes256Gcm(secret);
  const decrypted = CryptoService.decryptAes256Gcm(encrypted);
  console.log('AES-256-GCM Roundtrip:', decrypted === secret ? 'PASS' : 'FAIL');

  // Test SHA-256
  const digest1 = CryptoService.sha256('token123');
  const digest2 = CryptoService.sha256('token123');
  console.log('SHA-256 Deterministic:', digest1 === digest2 ? 'PASS' : 'FAIL');

  // Test TimingSafeEqual
  console.log('TimingSafeEqual Match:', CryptoService.timingSafeEqual('abc', 'abc') ? 'PASS' : 'FAIL');
  console.log('TimingSafeEqual Mismatch:', !CryptoService.timingSafeEqual('abc', 'abd') ? 'PASS' : 'FAIL');

  console.log('Crypto tests completed successfully!');
}

runTest().catch((err) => {
  console.error(err);
  process.exit(1);
});
