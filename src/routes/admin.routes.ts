import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { requireAdminApiKey } from '../middleware/admin.middleware.js';
import { adminSendUpdateSchema } from '../schemas/admin.schema.js';
import { prisma } from '../database/prisma.js';
import { EmailService } from '../services/email.service.js';

export const adminRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  /**
   * POST /admin/send-update
   * Broadcasts game updates and announcements to all users opted into marketing with verified emails.
   * Protected strictly by `x-admin-api-key` header.
   */
  fastify.post(
    '/send-update',
    { preHandler: [requireAdminApiKey] },
    async (request, reply) => {
      const body = adminSendUpdateSchema.parse(request.body);

      // Query verified users with marketing opt-in
      const optedInUsers = await prisma.user.findMany({
        where: {
          marketing_opt_in: true,
          email_verified: true,
          email: { not: null },
        },
        select: {
          email: true,
        },
      });

      const recipientEmails = optedInUsers
        .map((u) => u.email)
        .filter((e): e is string => typeof e === 'string');

      if (recipientEmails.length === 0) {
        return reply.send({
          success: true,
          message: 'No opted-in verified recipients found.',
          total_recipients: 0,
          sent: 0,
          failed: 0,
        });
      }

      const textFallback =
        body.text_content ||
        body.html_content.replace(/<[^>]*>?/gm, ' ').replace(/\s+/g, ' ').trim();

      const result = await EmailService.sendMarketingBatch(
        recipientEmails,
        body.subject,
        body.html_content,
        textFallback
      );

      return reply.send({
        success: true,
        message: `Dispatched announcement to ${result.sent} players.`,
        total_recipients: recipientEmails.length,
        sent: result.sent,
        failed: result.failed,
      });
    }
  );
};
