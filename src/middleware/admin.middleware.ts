import { FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config/env.js';
import { CryptoService } from '../services/crypto.service.js';

export async function requireAdminApiKey(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const headerKey =
    request.headers['x-admin-api-key'] ||
    (request.headers.authorization?.startsWith('Bearer ')
      ? request.headers.authorization.substring(7)
      : null);

  if (typeof headerKey !== 'string') {
    return reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing required admin API key header (x-admin-api-key)',
    });
  }

  const isValid = CryptoService.timingSafeEqual(headerKey, config.ADMIN_API_KEY);

  if (!isValid) {
    return reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Invalid admin API key credentials',
    });
  }
}
