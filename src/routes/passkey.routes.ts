import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { authenticate } from '../middleware/auth.middleware.js';
import {
  passkeyLoginOptionsSchema,
  passkeyRegisterVerifySchema,
  passkeyLoginVerifySchema,
} from '../schemas/passkey.schema.js';
import { WebAuthnService } from '../services/webauthn.service.js';
import { TokenService } from '../services/token.service.js';

export const passkeyRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  /**
   * POST /auth/passkey/register-options
   * Initiates biometric / hardware passkey registration for an authenticated user.
   */
  fastify.post('/register-options', { preHandler: [authenticate] }, async (request, reply) => {
    const user = request.user!;
    const options = await WebAuthnService.generatePasskeyRegistrationOptions(
      user.sub,
      user.username
    );

    return reply.send(options);
  });

  /**
   * POST /auth/passkey/register-verify
   * Verifies passkey creation and stores credential in PostgreSQL.
   */
  fastify.post('/register-verify', { preHandler: [authenticate] }, async (request, reply) => {
    const user = request.user!;
    const body = passkeyRegisterVerifySchema.parse(request.body);

    try {
      const result = await WebAuthnService.verifyPasskeyRegistration(
        user.sub,
        body.response as any
      );

      return reply.send({
        success: true,
        message: 'Passkey enrolled successfully.',
        credential_id: result.credentialId,
      });
    } catch (err) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: (err as Error).message,
      });
    }
  });

  /**
   * POST /auth/passkey/login-options
   * Generates authentication challenge for passkey sign-in.
   */
  fastify.post('/login-options', async (request, reply) => {
    const body = passkeyLoginOptionsSchema.parse(request.body || {});
    const options = await WebAuthnService.generatePasskeyLoginOptions(body.identifier);

    return reply.send(options);
  });

  /**
   * POST /auth/passkey/login-verify
   * Verifies biometric passkey authentication and issues session tokens.
   */
  fastify.post('/login-verify', async (request, reply) => {
    const body = passkeyLoginVerifySchema.parse(request.body);

    try {
      const user = await WebAuthnService.verifyPasskeyLogin(body.response as any);

      // Issue tokens
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
        message: 'Passkey authentication successful.',
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
    } catch (err) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: (err as Error).message,
      });
    }
  });
};
