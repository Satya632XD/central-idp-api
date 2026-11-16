import { redis } from '../database/redis.js';
import { CONSTANTS } from '../config/constants.js';
import { CryptoService } from './crypto.service.js';

export type OtpPurpose = 'register' | 'password_reset';

export interface VerifyOtpResult {
  valid: boolean;
  message?: string;
  locked?: boolean;
}

export class OtpService {
  /**
   * Generates a 6-digit numeric OTP, computes its SHA-256 hash, and stores it in Redis.
   * Enforces OTP TTL (5 mins for register, 10 mins for password_reset).
   */
  static async createAndStoreOtp(
    identifier: string,
    purpose: OtpPurpose
  ): Promise<string> {
    const otp = CryptoService.generateNumericOtp(CONSTANTS.OTP_LENGTH);
    const otpHash = CryptoService.sha256(otp);

    const ttlSeconds =
      purpose === 'register'
        ? CONSTANTS.OTP_REGISTER_TTL_SECONDS
        : CONSTANTS.OTP_PASSWORD_RESET_TTL_SECONDS;

    const otpKey = CONSTANTS.REDIS_KEYS.OTP(purpose, identifier);
    const attemptsKey = CONSTANTS.REDIS_KEYS.OTP_ATTEMPTS(purpose, identifier);

    // Atomic write of hashed OTP and reset attempts
    await redis
      .multi()
      .set(otpKey, otpHash, 'EX', ttlSeconds)
      .set(attemptsKey, '0', 'EX', ttlSeconds)
      .exec();

    return otp;
  }

  /**
   * Verifies the provided 6-digit OTP against the stored SHA-256 hash.
   * Enforces a maximum of 5 attempts before complete lockout and revocation.
   */
  static async verifyOtp(
    identifier: string,
    code: string,
    purpose: OtpPurpose
  ): Promise<VerifyOtpResult> {
    const otpKey = CONSTANTS.REDIS_KEYS.OTP(purpose, identifier);
    const attemptsKey = CONSTANTS.REDIS_KEYS.OTP_ATTEMPTS(purpose, identifier);

    const [storedHash, attemptsStr] = await Promise.all([
      redis.get(otpKey),
      redis.get(attemptsKey),
    ]);

    if (!storedHash) {
      return {
        valid: false,
        message: 'OTP has expired or does not exist. Please request a new code.',
      };
    }

    const currentAttempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;
    if (currentAttempts >= CONSTANTS.OTP_MAX_VERIFY_ATTEMPTS) {
      // Exceeded max attempts: delete OTP key to lock out and prevent brute force
      await redis.del(otpKey, attemptsKey);
      return {
        valid: false,
        locked: true,
        message: 'Maximum OTP verification attempts exceeded. Code invalidated.',
      };
    }

    const inputHash = CryptoService.sha256(code.trim());
    const isMatch = CryptoService.timingSafeEqual(inputHash, storedHash);

    if (isMatch) {
      // Invalidate OTP immediately upon successful verification to prevent replay
      await redis.del(otpKey, attemptsKey);
      return { valid: true };
    }

    // Increment attempts on failure
    const newAttempts = await redis.incr(attemptsKey);
    const remainingAttempts = Math.max(0, CONSTANTS.OTP_MAX_VERIFY_ATTEMPTS - newAttempts);

    if (newAttempts >= CONSTANTS.OTP_MAX_VERIFY_ATTEMPTS) {
      await redis.del(otpKey, attemptsKey);
      return {
        valid: false,
        locked: true,
        message: 'Maximum OTP verification attempts exceeded. Code invalidated.',
      };
    }

    return {
      valid: false,
      message: `Invalid verification code. ${remainingAttempts} attempts remaining.`,
    };
  }
}
