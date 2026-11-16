import { redis } from '../database/redis.js';
import { CONSTANTS } from '../config/constants.js';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetInSeconds: number;
}

export class RateLimitService {
  /**
   * Generic atomic counter-based rate limiter using Redis INCR and EXPIRE.
   */
  private static async checkAndIncrement(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    try {
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, windowSeconds);
      }

      const ttl = await redis.ttl(key);
      const remaining = Math.max(0, limit - current);

      return {
        allowed: current <= limit,
        remaining,
        resetInSeconds: ttl > 0 ? ttl : windowSeconds,
      };
    } catch (err) {
      console.warn(`Rate limiter Redis error for key ${key}:`, (err as Error).message);
      // Fail open or closed depending on threat profile; for auth security, permit with fallback
      return { allowed: true, remaining: limit, resetInSeconds: windowSeconds };
    }
  }

  /**
   * Checks login rate limit for both IP address and username/identifier.
   * Max 5 attempts per 15 minutes.
   */
  static async checkLoginRateLimit(
    identifier: string,
    ip: string
  ): Promise<RateLimitResult> {
    const idKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`user:${identifier}`);
    const ipKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`ip:${ip}`);

    const [idRes, ipRes] = await Promise.all([
      this.checkStatus(idKey, CONSTANTS.RATE_LIMIT_LOGIN.MAX_ATTEMPTS, CONSTANTS.RATE_LIMIT_LOGIN.WINDOW_SECONDS),
      this.checkStatus(ipKey, CONSTANTS.RATE_LIMIT_LOGIN.MAX_ATTEMPTS, CONSTANTS.RATE_LIMIT_LOGIN.WINDOW_SECONDS),
    ]);

    if (!idRes.allowed || !ipRes.allowed) {
      return {
        allowed: false,
        remaining: Math.min(idRes.remaining, ipRes.remaining),
        resetInSeconds: Math.max(idRes.resetInSeconds, ipRes.resetInSeconds),
      };
    }

    return {
      allowed: true,
      remaining: Math.min(idRes.remaining, ipRes.remaining),
      resetInSeconds: Math.max(idRes.resetInSeconds, ipRes.resetInSeconds),
    };
  }

  /**
   * Increments failed login attempt counter.
   */
  static async recordFailedLogin(identifier: string, ip: string): Promise<void> {
    const idKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`user:${identifier}`);
    const ipKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`ip:${ip}`);

    await Promise.all([
      this.incrementKey(idKey, CONSTANTS.RATE_LIMIT_LOGIN.WINDOW_SECONDS),
      this.incrementKey(ipKey, CONSTANTS.RATE_LIMIT_LOGIN.WINDOW_SECONDS),
    ]);
  }

  /**
   * Resets login rate limit counter on successful authentication.
   */
  static async clearLoginAttempts(identifier: string, ip: string): Promise<void> {
    const idKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`user:${identifier}`);
    const ipKey = CONSTANTS.REDIS_KEYS.RATE_LIMIT_LOGIN(`ip:${ip}`);
    try {
      await redis.del(idKey, ipKey);
    } catch (err) {
      console.warn('Failed to clear login rate limit in Redis:', (err as Error).message);
    }
  }

  /**
   * Checks and consumes OTP request rate limit.
   * Max 3 requests per 10 minutes per email/phone.
   */
  static async consumeOtpRequest(identifier: string): Promise<RateLimitResult> {
    const key = CONSTANTS.REDIS_KEYS.RATE_LIMIT_OTP(identifier);
    return this.checkAndIncrement(
      key,
      CONSTANTS.RATE_LIMIT_OTP.MAX_ATTEMPTS,
      CONSTANTS.RATE_LIMIT_OTP.WINDOW_SECONDS
    );
  }

  private static async checkStatus(
    key: string,
    limit: number,
    windowSeconds: number
  ): Promise<RateLimitResult> {
    try {
      const currentVal = await redis.get(key);
      const current = currentVal ? parseInt(currentVal, 10) : 0;
      const ttl = await redis.ttl(key);

      return {
        allowed: current < limit,
        remaining: Math.max(0, limit - current),
        resetInSeconds: ttl > 0 ? ttl : windowSeconds,
      };
    } catch {
      return { allowed: true, remaining: limit, resetInSeconds: windowSeconds };
    }
  }

  private static async incrementKey(key: string, windowSeconds: number): Promise<void> {
    try {
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, windowSeconds);
      }
    } catch (err) {
      console.warn(`Redis increment error for key ${key}:`, (err as Error).message);
    }
  }
}
