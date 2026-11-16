import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { prisma } from '../database/prisma.js';
import { redis } from '../database/redis.js';
import { config } from '../config/env.js';
import { CONSTANTS } from '../config/constants.js';

export class WebAuthnService {
  /**
   * Generates WebAuthn registration options for an authenticated user.
   */
  static async generatePasskeyRegistrationOptions(userId: string, username: string) {
    const existingCredentials = await prisma.webauthnCredential.findMany({
      where: { user_id: userId },
      select: { id: true, transports: true },
    });

    const options = await generateRegistrationOptions({
      rpName: config.RP_NAME,
      rpID: config.RP_ID,
      userID: Buffer.from(userId, 'utf-8'),
      userName: username,
      attestationType: 'none',
      excludeCredentials: existingCredentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports as any,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    // Save challenge in Redis for 5 minutes
    const challengeKey = CONSTANTS.REDIS_KEYS.PASSKEY_CHALLENGE(`reg:${userId}`);
    await redis.set(challengeKey, options.challenge, 'EX', 300);

    return options;
  }

  /**
   * Verifies WebAuthn registration response and registers credential.
   */
  static async verifyPasskeyRegistration(
    userId: string,
    response: RegistrationResponseJSON
  ) {
    const challengeKey = CONSTANTS.REDIS_KEYS.PASSKEY_CHALLENGE(`reg:${userId}`);
    const expectedChallenge = await redis.get(challengeKey);

    if (!expectedChallenge) {
      throw new Error('Registration challenge expired or not found. Please try again.');
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.RP_ORIGIN,
      expectedRPID: config.RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Passkey registration verification failed');
    }

    const { credential } = verification.registrationInfo;

    // Save credential in PostgreSQL
    await prisma.webauthnCredential.create({
      data: {
        id: credential.id,
        user_id: userId,
        public_key: Buffer.from(credential.publicKey),
        counter: BigInt(credential.counter),
        transports: credential.transports || [],
      },
    });

    // Clean up challenge
    await redis.del(challengeKey);

    return { success: true, credentialId: credential.id };
  }

  /**
   * Generates WebAuthn authentication options for passkey login.
   */
  static async generatePasskeyLoginOptions(identifier?: string) {
    let allowedCredentials: { id: string; transports?: any[] }[] = [];
    let userId: string | null = null;

    if (identifier) {
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: identifier },
            { email: identifier },
            { phone_number: identifier },
          ],
        },
        include: { webauthn_credentials: true },
      });

      if (user) {
        userId = user.id;
        allowedCredentials = user.webauthn_credentials.map((c) => ({
          id: c.id,
          transports: c.transports as any,
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: config.RP_ID,
      userVerification: 'preferred',
      allowCredentials: allowedCredentials.length > 0 ? allowedCredentials : undefined,
    });

    // Save challenge in Redis
    const challengeKey = CONSTANTS.REDIS_KEYS.PASSKEY_CHALLENGE(
      `auth:${options.challenge}`
    );
    await redis.set(
      challengeKey,
      JSON.stringify({ challenge: options.challenge, userId }),
      'EX',
      300
    );

    return options;
  }

  /**
   * Verifies WebAuthn authentication response and returns authenticated user.
   */
  static async verifyPasskeyLogin(response: AuthenticationResponseJSON) {
    const credentialId = response.id;

    // Find registered credential in PostgreSQL
    const credential = await prisma.webauthnCredential.findUnique({
      where: { id: credentialId },
      include: { user: true },
    });

    if (!credential) {
      throw new Error('Unknown or unregistered passkey credential');
    }

    // Retrieve challenge using response's clientDataJSON challenge or challenge key
    // We search the challenge key stored during options generation
    const challengeKey = CONSTANTS.REDIS_KEYS.PASSKEY_CHALLENGE(
      `auth:${response.response.clientDataJSON ? '' : ''}`
    );

    // Look up challenge from Redis
    const clientDataParsed = JSON.parse(
      Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf-8')
    );
    const clientChallenge = clientDataParsed.challenge;
    const redisKey = CONSTANTS.REDIS_KEYS.PASSKEY_CHALLENGE(`auth:${clientChallenge}`);

    const storedData = await redis.get(redisKey);
    if (!storedData) {
      throw new Error('Passkey login challenge expired or invalid');
    }

    const { challenge: expectedChallenge } = JSON.parse(storedData);

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.RP_ORIGIN,
      expectedRPID: config.RP_ID,
      credential: {
        id: credential.id,
        publicKey: new Uint8Array(credential.public_key),
        counter: Number(credential.counter),
        transports: credential.transports as any,
      },
    });

    if (!verification.verified || !verification.authenticationInfo) {
      throw new Error('Passkey signature verification failed');
    }

    // Counter rollback check / update
    await prisma.webauthnCredential.update({
      where: { id: credential.id },
      data: {
        counter: BigInt(verification.authenticationInfo.newCounter),
      },
    });

    // Clean up challenge
    await redis.del(redisKey);

    return credential.user;
  }
}
