import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default('0.0.0.0'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  FRONTEND_URL: z.string().default('http://localhost:3000'),
  CORS_ORIGIN: z.string().default('*'),

  // PostgreSQL (Neon)
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_URL_UNPOOLED: z.string().optional(),
  NEON_BRANCH: z.string().optional(),
  NEON_BRANCH_ID: z.string().optional(),
  NEON_FUNCTION_HOST_SUFFIX: z.string().optional(),

  // Redis (Upstash)
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),

  // JWT Configuration
  JWT_KEY_ID: z.string().min(1, 'JWT_KEY_ID is required'),
  JWT_ISSUER: z.string().default('https://auth.centralidp.io'),
  JWT_AUDIENCE: z.string().default('central-idp-clients'),
  JWT_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900),
  JWT_REFRESH_TOKEN_TTL_DAYS: z.coerce.number().default(30),
  JWT_PRIVATE_KEY: z.string().min(1, 'JWT_PRIVATE_KEY is required'),
  JWT_PUBLIC_KEY: z.string().min(1, 'JWT_PUBLIC_KEY is required'),

  // Security & Encryption
  ENCRYPTION_KEY: z
    .string()
    .length(64, 'ENCRYPTION_KEY must be a 64-character hex string (32 bytes)'),
  ADMIN_API_KEY: z.string().min(16, 'ADMIN_API_KEY must be at least 16 characters'),

  // Email (Resend)
  RESEND_API_KEY: z.string().min(1, 'RESEND_API_KEY is required'),
  RESEND_FROM_EMAIL: z.string().email().default('noreply@centralidp.io'),

  // SMS (Twilio)
  TWILIO_ACCOUNT_SID: z.string().default(''),
  TWILIO_AUTH_TOKEN: z.string().default(''),
  TWILIO_PHONE_NUMBER: z.string().default(''),

  // Passkeys / WebAuthn
  RP_NAME: z.string().default('Central Gaming IdP'),
  RP_ID: z.string().default('localhost'),
  RP_ORIGIN: z.string().default('http://localhost:3000'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('CRITICAL: Environment validation failed:');
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1);
}

// Convert escaped newlines in keys if loaded from single-line string
const rawEnv = parsed.data;
export const config = {
  ...rawEnv,
  JWT_PRIVATE_KEY: rawEnv.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'),
  JWT_PUBLIC_KEY: rawEnv.JWT_PUBLIC_KEY.replace(/\\n/g, '\n'),
};
