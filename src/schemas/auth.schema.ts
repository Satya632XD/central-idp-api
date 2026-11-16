import { z } from 'zod';

const E164_REGEX = /^\+[1-9]\d{1,14}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,100}$/;

export const registerSchema = z
  .object({
    username: z
      .string()
      .min(3, 'Username must be at least 3 characters')
      .max(30, 'Username must not exceed 30 characters')
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username may only contain letters, numbers, underscores, and hyphens'),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .max(100, 'Password is too long')
      .regex(
        PASSWORD_REGEX,
        'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character'
      ),
    email: z.string().email('Invalid email address format').optional().nullable(),
    phone_number: z
      .string()
      .regex(E164_REGEX, 'Phone number must be in international E.164 format (e.g. +14155552671)')
      .optional()
      .nullable(),
    marketing_opt_in: z.boolean().default(false),
  })
  .refine(
    (data) => Boolean(data.email || data.phone_number),
    {
      message: 'Either email or phone_number must be provided to create an account',
      path: ['email'],
    }
  );

export const verifyOtpSchema = z.object({
  identifier: z.string().min(3, 'Identifier is required'),
  code: z.string().regex(/^\d{6}$/, 'Verification code must be exactly 6 digits'),
  purpose: z.enum(['register', 'password_reset']).default('register'),
});

export const loginSchema = z.object({
  identifier: z.string().min(1, 'Username, email, or phone number is required'),
  password: z.string().min(1, 'Password is required'),
  device_fingerprint: z.string().max(255).optional(),
});

export const passwordResetRequestSchema = z.object({
  identifier: z.string().min(1, 'Email or phone number is required'),
});

export const passwordResetConfirmSchema = z.object({
  identifier: z.string().min(1, 'Identifier is required'),
  code: z.string().regex(/^\d{6}$/, 'Verification code must be exactly 6 digits'),
  new_password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password is too long')
    .regex(
      PASSWORD_REGEX,
      'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character'
    ),
});

export const refreshTokenSchema = z.object({
  refresh_token: z.string().min(20, 'Invalid refresh token'),
  device_fingerprint: z.string().max(255).optional(),
});

export const logoutSchema = z.object({
  refresh_token: z.string().min(20, 'Invalid refresh token'),
});

export const revokeAllSchema = z.object({
  revoke_token: z.string().optional(),
});
