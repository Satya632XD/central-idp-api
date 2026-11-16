import { createRequire } from 'node:module';
import { redis } from '../database/redis.js';
import { prisma } from '../database/prisma.js';
import { CONSTANTS } from '../config/constants.js';
import { config } from '../config/env.js';
import { CryptoService } from './crypto.service.js';

const require = createRequire(import.meta.url);
const { generateSecret, generateURI, verifySync } = require('otplib');

export interface TotpSetupResponse {
  secret: string;
  otpauth_url: string;
}

export class TotpService {
  /**
   * Initializes 2FA setup for an authenticated user.
   * Generates Base32 secret, builds otpauth:// URI, encrypts secret with AES-256-GCM,
   * and stages it in Redis with a 10-minute TTL pending verification.
   */
  static async generateSetup(userId: string, username: string): Promise<TotpSetupResponse> {
    const secret: string = generateSecret();
    const otpauthUrl: string = generateURI({
      secret,
      label: username,
      issuer: config.RP_NAME,
    });

    const encryptedSecret = CryptoService.encryptAes256Gcm(secret);
    const key = CONSTANTS.REDIS_KEYS.TOTP_SETUP(userId);

    // Save encrypted secret in Redis with 10-minute TTL
    await redis.set(key, encryptedSecret, 'EX', 600);

    return {
      secret,
      otpauth_url: otpauthUrl,
    };
  }

  /**
   * Confirms 2FA setup by verifying the user's first 6-digit TOTP code.
   * Saves the encrypted secret to PostgreSQL and enables totp_enabled flag.
   */
  static async confirmSetup(userId: string, code: string): Promise<boolean> {
    const key = CONSTANTS.REDIS_KEYS.TOTP_SETUP(userId);
    const encryptedSecret = await redis.get(key);

    if (!encryptedSecret) {
      throw new Error('TOTP setup session expired. Please restart 2FA setup.');
    }

    const secret = CryptoService.decryptAes256Gcm(encryptedSecret);
    const result = verifySync({ token: code.trim(), secret });

    if (!result || !result.valid) {
      return false;
    }

    // Persist encrypted secret into PostgreSQL and mark TOTP enabled
    await prisma.user.update({
      where: { id: userId },
      data: {
        totp_secret_encrypted: encryptedSecret,
        totp_enabled: true,
      },
    });

    // Cleanup Redis staging key
    await redis.del(key);
    return true;
  }

  /**
   * Verifies a 6-digit TOTP code during user authentication.
   */
  static async verifyLogin(userId: string, code: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { totp_enabled: true, totp_secret_encrypted: true },
    });

    if (!user || !user.totp_enabled || !user.totp_secret_encrypted) {
      throw new Error('2FA is not enabled for this user');
    }

    const secret = CryptoService.decryptAes256Gcm(user.totp_secret_encrypted);
    const result = verifySync({ token: code.trim(), secret });

    return !!result && !!result.valid;
  }
}
