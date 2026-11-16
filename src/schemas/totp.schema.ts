import { z } from 'zod';

export const totpVerifySchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'TOTP code must be exactly 6 digits'),
  temp_token: z.string().optional(),
});
