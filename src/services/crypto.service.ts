import * as crypto from 'node:crypto';
import * as argon2 from 'argon2';
import { CONSTANTS } from '../config/constants.js';
import { config } from '../config/env.js';

export class CryptoService {
  private static encryptionKeyBuffer = Buffer.from(config.ENCRYPTION_KEY, 'hex');

  /**
   * Hashes a password using Argon2id with RFC 9106 recommended parameters.
   */
  static async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, CONSTANTS.ARGON2_OPTIONS);
  }

  /**
   * Verifies a plain text password against an Argon2id hash.
   */
  static async verifyPassword(hash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plain);
    } catch {
      return false;
    }
  }

  /**
   * Encrypts plaintext data using AES-256-GCM.
   * Outputs format: `ivHex:authTagHex:ciphertextHex`
   */
  static encryptAes256Gcm(plaintext: string): string {
    const iv = crypto.randomBytes(CONSTANTS.AES_IV_LENGTH_BYTES);
    const cipher = crypto.createCipheriv(
      CONSTANTS.AES_ALGORITHM,
      this.encryptionKeyBuffer,
      iv
    );

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Decrypts AES-256-GCM ciphertext created by `encryptAes256Gcm`.
   */
  static decryptAes256Gcm(encryptedString: string): string {
    const parts = encryptedString.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted payload format');
    }

    const [ivHex, authTagHex, ciphertextHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const ciphertext = Buffer.from(ciphertextHex, 'hex');

    const decipher = crypto.createDecipheriv(
      CONSTANTS.AES_ALGORITHM,
      this.encryptionKeyBuffer,
      iv
    );

    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Computes a SHA-256 digest of a string (e.g. for refresh tokens or OTP comparison).
   */
  static sha256(data: string): string {
    return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
  }

  /**
   * Generates a cryptographically secure random token (hex-encoded).
   */
  static generateRandomToken(byteLength = 64): string {
    return crypto.randomBytes(byteLength).toString('hex');
  }

  /**
   * Generates a cryptographically secure numeric OTP string (default: 6 digits).
   */
  static generateNumericOtp(digits = 6): string {
    const min = Math.pow(10, digits - 1);
    const max = Math.pow(10, digits);
    const intVal = crypto.randomInt(min, max);
    return intVal.toString();
  }

  /**
   * Constant-time string comparison to prevent timing side-channel attacks.
   */
  static timingSafeEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) {
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }
}
