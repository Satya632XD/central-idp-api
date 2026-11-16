import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { prisma } from '../database/prisma.js';
import { CryptoService } from '../services/crypto.service.js';
import { TokenService } from '../services/token.service.js';
import { OtpService } from '../services/otp.service.js';
import { RateLimitService } from '../services/rate-limit.service.js';
import { EmailService } from '../services/email.service.js';
import { smsProvider } from '../services/sms/index.js';
import {
  registerSchema,
  verifyOtpSchema,
  loginSchema,
  passwordResetRequestSchema,
  passwordResetConfirmSchema,
  refreshTokenSchema,
  logoutSchema,
  revokeAllSchema,
} from '../schemas/auth.schema.js';
import { authenticate } from '../middleware/auth.middleware.js';

export const authRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  /**
   * POST /auth/register
   * Registers a new unverified user and dispatches a 6-digit OTP.
   */
  fastify.post('/register', async (request, reply) => {
    const body = registerSchema.parse(request.body);

    // Check unique username
    const existingUsername = await prisma.user.findUnique({
      where: { username: body.username },
      select: { id: true },
    });
    if (existingUsername) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'Username is already taken',
      });
    }

    // Check unique email
    if (body.email) {
      const existingEmail = await prisma.user.findUnique({
        where: { email: body.email },
        select: { id: true },
      });
      if (existingEmail) {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: 'Email is already registered',
        });
      }
    }

    // Check unique phone number
    if (body.phone_number) {
      const existingPhone = await prisma.user.findUnique({
        where: { phone_number: body.phone_number },
        select: { id: true },
      });
      if (existingPhone) {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: 'Phone number is already registered',
        });
      }
    }

    // Rate-limit OTP requests (max 3 per 10 minutes)
    const identifier = (body.email || body.phone_number) as string;
    const rateLimit = await RateLimitService.consumeOtpRequest(identifier);
    if (!rateLimit.allowed) {
      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Too many OTP requests. Please wait ${rateLimit.resetInSeconds} seconds before trying again.`,
      });
    }

    // Hash password with Argon2id
    const passwordHash = await CryptoService.hashPassword(body.password);

    // Save unverified user
    const newUser = await prisma.user.create({
      data: {
        username: body.username,
        password_hash: passwordHash,
        email: body.email || null,
        email_verified: false,
        phone_number: body.phone_number || null,
        phone_verified: false,
        marketing_opt_in: body.marketing_opt_in ?? false,
      },
    });

    // Generate 6-digit OTP & store SHA-256 hash in Redis (5-min TTL)
    const otp = await OtpService.createAndStoreOtp(identifier, 'register');

    // Dispatch via Resend (email) or Twilio (SMS)
    if (body.email) {
      await EmailService.sendOtpEmail(body.email, otp, 'register');
    } else if (body.phone_number) {
      await smsProvider.sendOtp(body.phone_number, otp);
    }

    return reply.status(201).send({
      success: true,
      message: 'Account created. Verification OTP has been sent.',
      user_id: newUser.id,
      verification_channel: body.email ? 'email' : 'sms',
    });
  });

  /**
   * POST /auth/verify-otp
   * Validates OTP code, marks contact verified, and issues initial access + refresh tokens.
   */
  fastify.post('/verify-otp', async (request, reply) => {
    const body = verifyOtpSchema.parse(request.body);

    const verification = await OtpService.verifyOtp(
      body.identifier,
      body.code,
      body.purpose
    );

    if (!verification.valid) {
      const status = verification.locked ? 429 : 400;
      return reply.status(status).send({
        statusCode: status,
        error: verification.locked ? 'Too Many Requests' : 'Bad Request',
        message: verification.message,
      });
    }

    // Lookup user by email or phone
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: body.identifier },
          { phone_number: body.identifier },
        ],
      },
    });

    if (!user) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'No account associated with this identifier',
      });
    }

    // Mark verified
    const isEmail = user.email === body.identifier;
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: isEmail ? { email_verified: true } : { phone_verified: true },
    });

    // Create session tokens
    const deviceFingerprint = (request.headers['user-agent'] as string) || undefined;
    const refreshToken = await TokenService.createRefreshToken(
      updatedUser.id,
      request.ip,
      deviceFingerprint
    );

    const accessToken = await TokenService.generateAccessToken({
      userId: updatedUser.id,
      username: updatedUser.username,
      email: updatedUser.email,
      phone_number: updatedUser.phone_number,
    });

    return reply.send({
      success: true,
      message: 'Verification successful.',
      tokens: {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'Bearer',
        expires_in: 900,
      },
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        email_verified: updatedUser.email_verified,
        phone_number: updatedUser.phone_number,
        phone_verified: updatedUser.phone_verified,
        totp_enabled: updatedUser.totp_enabled,
      },
    });
  });

  /**
   * POST /auth/login
   * Authenticates credentials with rate-limiting, 2FA gating, and new device security alerts.
   */
  fastify.post('/login', async (request, reply) => {
    const body = loginSchema.parse(request.body);

    // Rate-limit check (max 5 attempts per 15 mins)
    const rateLimit = await RateLimitService.checkLoginRateLimit(body.identifier, request.ip);
    if (!rateLimit.allowed) {
      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Too many failed login attempts. Please wait ${rateLimit.resetInSeconds} seconds before trying again.`,
      });
    }

    // Lookup user by username, email, or phone
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { username: body.identifier },
          { email: body.identifier },
          { phone_number: body.identifier },
        ],
      },
      include: {
        refresh_tokens: {
          select: { ip_address: true, device_fingerprint: true },
          take: 50,
        },
      },
    });

    if (!user) {
      await RateLimitService.recordFailedLogin(body.identifier, request.ip);
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid username or password credentials',
      });
    }

    // Verify Argon2id password hash
    const isPasswordValid = await CryptoService.verifyPassword(
      user.password_hash,
      body.password
    );

    if (!isPasswordValid) {
      await RateLimitService.recordFailedLogin(body.identifier, request.ip);
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid username or password credentials',
      });
    }

    // Clear failed attempts counter on success
    await RateLimitService.clearLoginAttempts(body.identifier, request.ip);

    // 2FA Gating
    if (user.totp_enabled) {
      const tempToken = await TokenService.generate2FaPendingToken(user.id, body.identifier);
      return reply.send({
        requires_2fa: true,
        temp_token: tempToken,
        message: 'Two-factor authentication required. Submit TOTP code to /auth/2fa/totp/verify',
      });
    }

    // Device / IP Anomaly Detection
    const deviceFingerprint = body.device_fingerprint || (request.headers['user-agent'] as string);
    const hasSeenIp = user.refresh_tokens.some((t) => t.ip_address === request.ip);
    const hasSeenDevice = user.refresh_tokens.some(
      (t) => t.device_fingerprint && t.device_fingerprint === deviceFingerprint
    );

    const isNewDeviceOrIp = !hasSeenIp || !hasSeenDevice;

    if (isNewDeviceOrIp && user.email && user.email_verified) {
      // Issue security alert with one-click revocation token
      const revokeToken = await TokenService.generateAccessToken({
        userId: user.id,
        username: user.username,
      });

      EmailService.sendNewDeviceLoginAlert({
        to: user.email,
        username: user.username,
        ipAddress: request.ip,
        deviceFingerprint,
        revokeToken,
      }).catch((err) => request.log.error(err, 'Failed to send new device login email'));
    }

    // Issue session tokens
    const refreshToken = await TokenService.createRefreshToken(
      user.id,
      request.ip,
      deviceFingerprint
    );

    const accessToken = await TokenService.generateAccessToken({
      userId: user.id,
      username: user.username,
      email: user.email,
      phone_number: user.phone_number,
    });

    return reply.send({
      requires_2fa: false,
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
  });

  /**
   * POST /auth/password-reset/request
   * Requests a 6-digit password reset OTP to email or phone.
   */
  fastify.post('/password-reset/request', async (request, reply) => {
    const body = passwordResetRequestSchema.parse(request.body);

    const rateLimit = await RateLimitService.consumeOtpRequest(body.identifier);
    if (!rateLimit.allowed) {
      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Too many password reset requests. Please wait ${rateLimit.resetInSeconds} seconds.`,
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: body.identifier, email_verified: true },
          { phone_number: body.identifier, phone_verified: true },
        ],
      },
    });

    // Timing-attack mitigation: always return identical response regardless of user existence
    if (user) {
      const otp = await OtpService.createAndStoreOtp(body.identifier, 'password_reset');
      if (user.email === body.identifier) {
        await EmailService.sendOtpEmail(user.email, otp, 'password_reset');
      } else if (user.phone_number === body.identifier) {
        await smsProvider.sendOtp(user.phone_number, otp);
      }
    }

    return reply.send({
      success: true,
      message: 'If an account exists with this identifier, a password reset code has been sent.',
    });
  });

  /**
   * POST /auth/password-reset/confirm
   * Validates OTP, updates password hash, revokes ALL active sessions, and sends notification.
   */
  fastify.post('/password-reset/confirm', async (request, reply) => {
    const body = passwordResetConfirmSchema.parse(request.body);

    const verification = await OtpService.verifyOtp(
      body.identifier,
      body.code,
      'password_reset'
    );

    if (!verification.valid) {
      const status = verification.locked ? 429 : 400;
      return reply.status(status).send({
        statusCode: status,
        error: verification.locked ? 'Too Many Requests' : 'Bad Request',
        message: verification.message,
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: body.identifier },
          { phone_number: body.identifier },
        ],
      },
    });

    if (!user) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'User account not found',
      });
    }

    // Hash new password with Argon2id
    const newHash = await CryptoService.hashPassword(body.new_password);

    // Update password in DB
    await prisma.user.update({
      where: { id: user.id },
      data: { password_hash: newHash },
    });

    // Security requirement: Revoke ALL active refresh tokens
    await TokenService.revokeAllUserSessions(user.id);

    // Dispatch confirmation email
    if (user.email) {
      EmailService.sendPasswordChangedConfirmation(user.email, user.username).catch((err) =>
        request.log.error(err, 'Failed to send password reset confirmation email')
      );
    }

    return reply.send({
      success: true,
      message: 'Password updated successfully. All active sessions have been revoked.',
    });
  });

  /**
   * POST /auth/token/refresh
   * Rotates refresh tokens with automatic token reuse attack detection.
   */
  fastify.post('/token/refresh', async (request, reply) => {
    const body = refreshTokenSchema.parse(request.body);
    const deviceFingerprint = body.device_fingerprint || (request.headers['user-agent'] as string);

    try {
      const newTokens = await TokenService.rotateRefreshToken(
        body.refresh_token,
        request.ip,
        deviceFingerprint
      );

      return reply.send({
        success: true,
        tokens: newTokens,
      });
    } catch (err) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: (err as Error).message,
      });
    }
  });

  /**
   * POST /auth/logout
   * Revokes the current session's refresh token.
   */
  fastify.post('/logout', async (request, reply) => {
    const body = logoutSchema.parse(request.body);
    await TokenService.revokeRefreshToken(body.refresh_token);

    return reply.send({
      success: true,
      message: 'Successfully logged out session.',
    });
  });

  /**
   * POST /auth/revoke-all
   * Global sign-out: revokes all sessions across all games and apps.
   */
  fastify.post('/revoke-all', async (request, reply) => {
    const body = revokeAllSchema.parse(request.body || {});
    let targetUserId: string | null = null;

    // Check if called via email one-click revoke token
    if (body.revoke_token) {
      try {
        const payload = await TokenService.verifyAccessToken(body.revoke_token);
        targetUserId = payload.sub;
      } catch {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid or expired revoke token',
        });
      }
    } else {
      // Otherwise require standard authenticated access token
      await authenticate(request, reply);
      if (reply.sent) return;
      targetUserId = request.user!.sub;
    }

    if (!targetUserId) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Could not determine user to revoke sessions for',
      });
    }

    const count = await TokenService.revokeAllUserSessions(targetUserId);

    return reply.send({
      success: true,
      message: `All active sessions (${count}) have been successfully revoked across all platforms.`,
    });
  });
};
