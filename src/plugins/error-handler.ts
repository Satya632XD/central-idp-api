import { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';

export function errorHandler(
  error: FastifyError | Error,
  request: FastifyRequest,
  reply: FastifyReply
) {
  // Handle Zod input validation errors
  if (error instanceof ZodError) {
    const formattedErrors = (error.issues || []).map((e: any) => ({
      field: e.path.join('.'),
      message: e.message,
    }));

    return reply.status(400).send({
      type: 'https://problems.centralidp.io/validation-error',
      title: 'Invalid Request Payload',
      status: 400,
      detail: 'One or more fields failed validation checks',
      instance: request.url,
      errors: formattedErrors,
    });
  }

  // Handle Fastify HTTP errors
  const statusCode = (error as FastifyError).statusCode || 500;

  if (statusCode === 429) {
    return reply.status(429).send({
      type: 'https://problems.centralidp.io/rate-limit-exceeded',
      title: 'Rate Limit Exceeded',
      status: 429,
      detail: error.message || 'Too many requests. Please slow down and try again later.',
      instance: request.url,
    });
  }

  if (statusCode >= 400 && statusCode < 500) {
    return reply.status(statusCode).send({
      type: 'https://problems.centralidp.io/client-error',
      title: (error as FastifyError).name || 'Client Error',
      status: statusCode,
      detail: error.message,
      instance: request.url,
    });
  }

  // Internal Server Error (500) - Never leak sensitive DB error details to client!
  request.log.error(error, 'Unhandled Internal Server Error');

  return reply.status(500).send({
    type: 'https://problems.centralidp.io/internal-error',
    title: 'Internal Server Error',
    status: 500,
    detail: 'An unexpected internal error occurred. Our engineering team has been notified.',
    instance: request.url,
  });
}
