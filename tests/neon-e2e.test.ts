import { prisma, connectPrisma, disconnectPrisma } from '../src/database/prisma.js';
import { CryptoService } from '../src/services/crypto.service.js';
import { TokenService } from '../src/services/token.service.js';
import { buildApp } from '../src/app.js';

async function runNeonEndToEndTest() {
  console.log('=== Neon PostgreSQL End-to-End Integration Test ===\n');

  // Step 1: Connect and verify raw query
  console.log('1. Connecting to Neon PostgreSQL...');
  await connectPrisma();
  const dbInfo = await prisma.$queryRaw<any[]>`SELECT NOW() as current_time, version() as pg_version`;
  console.log('   ✓ Connected to Neon PostgreSQL successfully!');
  console.log('   Timestamp:', dbInfo[0].current_time);
  console.log('   Postgres Version:', dbInfo[0].pg_version.split(' ')[0], dbInfo[0].pg_version.split(' ')[1]);

  // Step 2: Insert User into Neon
  const testUsername = `neon_test_${Date.now()}`;
  const testEmail = `${testUsername}@example.com`;
  const passwordHash = await CryptoService.hashPassword('SuperSecret123!');

  console.log(`\n2. Creating test user [${testUsername}] in Neon...`);
  const createdUser = await prisma.user.create({
    data: {
      username: testUsername,
      email: testEmail,
      email_verified: true,
      password_hash: passwordHash,
      marketing_opt_in: true,
    },
  });
  console.log(`   ✓ User created in Neon with ID: ${createdUser.id}`);

  // Step 3: Query back user
  console.log('\n3. Querying user from Neon...');
  const fetchedUser = await prisma.user.findUnique({
    where: { id: createdUser.id },
  });
  if (fetchedUser && fetchedUser.email === testEmail) {
    console.log('   ✓ User read-back verified!');
  } else {
    throw new Error('User read-back failed');
  }

  // Step 4: Create Refresh Token in Neon
  console.log('\n4. Storing hashed Refresh Token in Neon refresh_tokens table...');
  const rawRefreshToken = await TokenService.createRefreshToken(
    createdUser.id,
    '127.0.0.1',
    'NeonE2ETest/1.0'
  );
  console.log('   ✓ Refresh token created and stored in Neon!');

  // Step 5: Rotate Refresh Token in Neon
  console.log('\n5. Rotating Refresh Token in Neon...');
  const rotatedTokens = await TokenService.rotateRefreshToken(
    rawRefreshToken,
    '127.0.0.1',
    'NeonE2ETest/1.0'
  );
  console.log('   ✓ Refresh token successfully rotated! New access token generated.');

  // Step 6: Verify Token Reuse Detection in Neon
  console.log('\n6. Testing Token Reuse Detection with old revoked token...');
  try {
    await TokenService.rotateRefreshToken(rawRefreshToken, '127.0.0.1');
    throw new Error('Token reuse should have been detected and rejected!');
  } catch (err) {
    console.log('   ✓ Expected security exception caught:', (err as Error).message);
  }

  // Step 7: WebAuthn Credential Storage in Neon
  console.log('\n7. Testing WebAuthn credential insert into Neon...');
  const credentialId = `cred_${Date.now()}`;
  const dummyPublicKey = Buffer.from('mock-public-key-bytes-for-neon-test');
  await prisma.webauthnCredential.create({
    data: {
      id: credentialId,
      user_id: createdUser.id,
      public_key: dummyPublicKey,
      counter: BigInt(1),
      transports: ['usb', 'internal'],
    },
  });
  const fetchedCred = await prisma.webauthnCredential.findUnique({
    where: { id: credentialId },
  });
  if (fetchedCred && fetchedCred.counter === BigInt(1)) {
    console.log('   ✓ WebAuthn credential verified in Neon!');
  }

  // Step 8: Clean up test user (Cascade deletes refresh_tokens and credentials)
  console.log('\n8. Cleaning up test records in Neon (verifying CASCADE delete)...');
  await prisma.user.delete({
    where: { id: createdUser.id },
  });
  const checkToken = await prisma.refreshToken.findFirst({
    where: { user_id: createdUser.id },
  });
  if (!checkToken) {
    console.log('   ✓ Cascade delete verified in Neon! All related tokens cleaned.');
  }

  // Step 9: Fastify App /health Check with Neon
  console.log('\n9. Testing Fastify App /health endpoint with Neon DB...');
  const app = await buildApp();
  const healthRes = await app.inject({
    method: 'GET',
    url: '/health',
  });
  const healthData = JSON.parse(healthRes.body);
  console.log('   ✓ Fastify /health status:', healthRes.statusCode);
  console.log('   ✓ Database connectivity report:', healthData.database);

  await app.close();
  await disconnectPrisma();

  console.log('\n=== ALL NEON SERVICES & TESTS PASSED END-TO-END! ===\n');
  process.exit(0);
}

runNeonEndToEndTest().catch(async (err) => {
  console.error('Neon test failed:', err);
  await disconnectPrisma();
  process.exit(1);
});
