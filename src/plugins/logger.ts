import { FastifyServerOptions } from 'fastify';
import { config } from '../config/env.js';

export const loggerConfig: FastifyServerOptions['logger'] = {
  level: config.NODE_ENV === 'production' ? 'info' : 'debug',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers["x-admin-api-key"]',
      'req.body.password',
      'req.body.new_password',
      'req.body.code',
      'req.body.otp',
      'req.body.refresh_token',
      'req.body.access_token',
      'req.body.temp_token',
      'req.body.secret',
      '*.password',
      '*.password_hash',
      '*.token',
      '*.code',
      '*.secret',
    ],
    censor: '[REDACTED_SECURITY_SENSITIVE]',
  },
  serializers: {
    req(request) {
      return {
        method: request.method,
        url: request.url,
        ip: request.ip,
        userAgent: request.headers['user-agent'],
      };
    },
    res(reply) {
      return {
        statusCode: reply.statusCode,
      };
    },
  },
};
