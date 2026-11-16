export const CONSTANTS = {
  // Token Lifespans
  ACCESS_TOKEN_TTL_SECONDS: 15 * 60, // 15 minutes
  REFRESH_TOKEN_TTL_DAYS: 30, // 30 days
  TWO_FACTOR_TEMP_TOKEN_TTL_SECONDS: 5 * 60, // 5 minutes

  // OTP Configurations
  OTP_LENGTH: 6,
  OTP_REGISTER_TTL_SECONDS: 5 * 60, // 5 minutes
  OTP_PASSWORD_RESET_TTL_SECONDS: 10 * 60, // 10 minutes
  OTP_MAX_VERIFY_ATTEMPTS: 5,

  // Rate Limiting Rules
  RATE_LIMIT_LOGIN: {
    MAX_ATTEMPTS: 5,
    WINDOW_SECONDS: 15 * 60, // 15 minutes
  },
  RATE_LIMIT_OTP: {
    MAX_ATTEMPTS: 3,
    WINDOW_SECONDS: 10 * 60, // 10 minutes
  },

  // Encryption Parameters
  AES_ALGORITHM: 'aes-256-gcm' as const,
  AES_IV_LENGTH_BYTES: 12, // 96-bit IV recommended for GCM
  AES_AUTH_TAG_LENGTH_BYTES: 16, // 128-bit authentication tag

  // Argon2id Parameters (RFC 9106 recommended profile)
  ARGON2_OPTIONS: {
    type: 2, // argon2id
    memoryCost: 65536, // 64 MB
    timeCost: 3, // 3 iterations
    parallelism: 4, // 4 threads
  },

  // Redis Key Prefixes
  REDIS_KEYS: {
    OTP: (purpose: string, identifier: string) => `otp:${purpose}:${identifier.toLowerCase()}`,
    OTP_ATTEMPTS: (purpose: string, identifier: string) => `otp_attempts:${purpose}:${identifier.toLowerCase()}`,
    TOTP_SETUP: (userId: string) => `totp:setup:${userId}`,
    PASSKEY_CHALLENGE: (userIdOrId: string) => `passkey:challenge:${userIdOrId}`,
    RATE_LIMIT_LOGIN: (identifier: string) => `ratelimit:login:${identifier.toLowerCase()}`,
    RATE_LIMIT_OTP: (identifier: string) => `ratelimit:otp:${identifier.toLowerCase()}`,
  },
} as const;
