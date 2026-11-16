import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { TokenService } from '../services/token.service.js';

export const jwksRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  /**
   * GET /.well-known/jwks.json
   * Exposes standard RS256 JWKS public key set.
   * Game backends (Unreal Engine Dedicated Servers, Unity Game Servers, Godot Servers)
   * consume this endpoint once and verify player access tokens offline with zero DB overhead!
   */
  fastify.get('/jwks.json', async (request, reply) => {
    const jwks = await TokenService.exportJwks();

    // Cache headers: cache for 24 hours
    reply.header('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
    reply.header('Content-Type', 'application/json');

    return reply.send(jwks);
  });
};
