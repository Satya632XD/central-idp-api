import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { authenticate } from '../middleware/auth.middleware.js';
import { totpVerifySchema } from '../schemas/totp.schema.js';
import { TotpService } from '../services/totp.service.js';
import { TokenService } from '../services/token.service.js';
import { prisma } from '../database/prisma.js';

export const totpRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  /**
   * POST /auth/2fa/totp/setup
   * Generates Base32 secret and otpauth URI. Encrypts secret with AES-256-GCM and stages in Redis.
   */
  fastify.post('/setup', { preHandler: [authenticate] }, async (request, reply) => {
    const user = request.user!;

    const setupData = await TotpService.generateSetup(user.sub, user.username);

    return reply.send({
      success: true,
      message: 'Scan the otpauth_url or enter the secret manually into your authenticator app.',
      ...setupData,
    });
  });

  /**
   * POST /auth/2fa/totp/verify
   * Dual-purpose endpoint:
   * 1. Confirms initial TOTP setup when authenticated with Bearer Access Token.
   * 2. Completes 2FA login when provided with a temp_token from /auth/login.
   */
  fastify.post('/verify', async (request, reply) => {
    const body = totpVerifySchema.parse(request.body);

    // Case 1: Completing 2FA Login via temp_token
    if (body.temp_token) {
      let tempPayload: { userId: string; identifier: string };
      try {
        tempPayload = await TokenService.verify2FaPendingToken(body.temp_token);
      } catch (err) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid or expired 2FA login session. Please login again.',
        });
      }

      const isValid = await TotpService.verifyLogin(tempPayload.userId, body.code);
      if (!isValid) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid two-factor authentication code',
        });
      }

      const user = await prisma.user.findUnique({
        where: { id: tempPayload.userId },
      });

      if (!user) {
        return reply.status(404).send({
          statusCode: 404,
          error: 'Not Found',
          message: 'User account not found',
        });
      }

      // Issue final session tokens
      const refreshToken = await TokenService.createRefreshToken(
        user.id,
        request.ip,
        request.headers['user-agent'] as string
      );

      const accessToken = await TokenService.generateAccessToken({
        userId: user.id,
        username: user.username,
        email: user.email,
        phone_number: user.phone_number,
      });

      return reply.send({
        success: true,
        message: 'Two-factor authentication verified successfully.',
        tokens: {
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: 'Bearer',
          expires_in: 900,
        },
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          phone_number: user.phone_number,
          email_verified: user.email_verified,
          phone_verified: user.phone_verified,
          totp_enabled: user.totp_enabled,
        },
      });
    }

    // Case 2: Confirming 2FA Setup for Authenticated User
    await authenticate(request, reply);
    if (reply.sent) return;

    try {
      const isConfirmed = await TotpService.confirmSetup(request.user!.sub, body.code);
      if (!isConfirmed) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'Invalid TOTP code. Setup could not be verified.',
        });
      }

      return reply.send({
        success: true,
        message: 'Two-factor authenticator app successfully activated.',
      });
    } catch (err) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: (err as Error).message,
      });
    }
  });
};
