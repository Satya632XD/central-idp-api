import { buildApp } from './app.js';
import { config } from './config/env.js';
import { connectPrisma, disconnectPrisma } from './database/prisma.js';
import { connectRedis, disconnectRedis } from './database/redis.js';

async function startServer() {
  const app = await buildApp();

  // Initialize DB and Cache connections
  await connectPrisma();
  await connectRedis();

  try {
    const address = await app.listen({
      port: config.PORT,
      host: config.HOST,
    });
    app.log.info(`Central IdP API listening on ${address}`);
    app.log.info(`Environment: ${config.NODE_ENV}`);
    app.log.info(`JWKS Endpoint: ${address}/.well-known/jwks.json`);
  } catch (err) {
    app.log.error(err, 'Server failed to start');
    process.exit(1);
  }

  // Graceful shutdown handling
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  for (const signal of signals) {
    process.on(signal, async () => {
      app.log.info(`Received ${signal}. Initiating graceful shutdown...`);
      try {
        await app.close();
        await disconnectPrisma();
        await disconnectRedis();
        app.log.info('Central IdP shutdown completed cleanly.');
        process.exit(0);
      } catch (shutdownErr) {
        app.log.error(shutdownErr, 'Error during graceful shutdown');
        process.exit(1);
      }
    });
  }
}

startServer();
