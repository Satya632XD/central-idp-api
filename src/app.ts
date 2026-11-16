import fastify, { FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import { config } from './config/env.js';
import { loggerConfig } from './plugins/logger.js';
import { errorHandler } from './plugins/error-handler.js';
import { prisma } from './database/prisma.js';
import { redis } from './database/redis.js';

import { authRoutes } from './routes/auth.routes.js';
import { totpRoutes } from './routes/totp.routes.js';
import { passkeyRoutes } from './routes/passkey.routes.js';
import { jwksRoutes } from './routes/jwks.routes.js';
import { adminRoutes } from './routes/admin.routes.js';

export async function buildApp(): Promise<FastifyInstance> {
  const app = fastify({
    logger: loggerConfig,
    trustProxy: true,
  });

  // Security Headers via Helmet
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    frameguard: { action: 'deny' },
  });

  // Cross-Origin Resource Sharing (CORS)
  await app.register(cors, {
    origin: config.CORS_ORIGIN === '*' ? true : config.CORS_ORIGIN.split(','),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-api-key'],
    credentials: true,
  });

  // Centralized Error Handling
  app.setErrorHandler(errorHandler);

  // Health Check Endpoint (used by Render and Docker healthchecks)
  app.get('/health', async (request, reply) => {
    let dbStatus = 'ok';
    let redisStatus = 'ok';

    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch {
      dbStatus = 'degraded';
    }

    try {
      await redis.ping();
    } catch {
      redisStatus = 'degraded';
    }

    const isHealthy = dbStatus === 'ok' && redisStatus === 'ok';

    return reply.status(isHealthy ? 200 : 503).send({
      status: isHealthy ? 'healthy' : 'degraded',
      database: dbStatus,
      redis: redisStatus,
      timestamp: new Date().toISOString(),
      uptime_seconds: process.uptime(),
    });
  });

  // Register Routes
  await app.register(authRoutes, { prefix: '/auth' });
  await app.register(totpRoutes, { prefix: '/auth/2fa/totp' });
  await app.register(passkeyRoutes, { prefix: '/auth/passkey' });
  await app.register(jwksRoutes, { prefix: '/.well-known' });
  await app.register(adminRoutes, { prefix: '/admin' });

  return app;
}
