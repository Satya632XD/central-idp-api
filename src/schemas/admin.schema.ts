import { z } from 'zod';

export const adminSendUpdateSchema = z.object({
  subject: z.string().min(3, 'Subject must be at least 3 characters'),
  html_content: z.string().min(1, 'HTML content is required'),
  text_content: z.string().optional(),
});
