import { FastifyRequest, FastifyReply } from 'fastify';
import { TokenService } from '../services/token.service.js';

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const authHeader = request.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing or malformed Authorization Bearer header',
    });
  }

  const token = authHeader.substring(7).trim();

  try {
    const payload = await TokenService.verifyAccessToken(token);
    request.user = payload;
  } catch (err) {
    return reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid or expired access token',
    });
  }
}
