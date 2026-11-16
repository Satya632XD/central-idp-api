import { z } from 'zod';

export const passkeyLoginOptionsSchema = z.object({
  identifier: z.string().optional(),
});

export const passkeyRegisterVerifySchema = z.object({
  response: z.record(z.string(), z.any()),
});

export const passkeyLoginVerifySchema = z.object({
  response: z.record(z.string(), z.any()),
});
