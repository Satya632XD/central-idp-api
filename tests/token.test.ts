import { TokenService } from '../src/services/token.service.js';

async function runTokenTest() {
  console.log('Testing TokenService...');

  // Test JWKS export
  const jwks = await TokenService.exportJwks();
  console.log('JWKS exported successfully:', jwks.keys.length === 1 && jwks.keys[0].kty === 'RSA' ? 'PASS' : 'FAIL');
  console.log('JWKS key ID:', jwks.keys[0].kid);

  // Test Access Token signing and verifying
  const token = await TokenService.generateAccessToken({
    userId: '123e4567-e89b-12d3-a456-426614174000',
    username: 'testplayer',
    email: 'player@example.com',
  });
  console.log('Access token generated:', token.startsWith('ey') ? 'PASS' : 'FAIL');

  const payload = await TokenService.verifyAccessToken(token);
  console.log('Access token verified payload:', payload.sub === '123e4567-e89b-12d3-a456-426614174000' && payload.username === 'testplayer' ? 'PASS' : 'FAIL');

  // Test 2FA Pending token
  const tempToken = await TokenService.generate2FaPendingToken('123e4567-e89b-12d3-a456-426614174000', 'player@example.com');
  const tempPayload = await TokenService.verify2FaPendingToken(tempToken);
  console.log('2FA pending token verified:', tempPayload.userId === '123e4567-e89b-12d3-a456-426614174000' ? 'PASS' : 'FAIL');

  console.log('Token tests completed successfully!');
}

runTokenTest().catch((err) => {
  console.error('Token test failed:', err);
  process.exit(1);
});
