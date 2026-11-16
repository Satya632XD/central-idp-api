import { PrismaClient } from '@prisma/client';
import { config } from '../config/env.js';

export const prisma = new PrismaClient({
  datasources: {
    db: {
      url: config.DATABASE_URL,
    },
  },
  log: config.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});

export async function connectPrisma(): Promise<void> {
  try {
    await prisma.$connect();
  } catch (error) {
    console.warn('Prisma initial connection deferred (will connect on first query):', (error as Error).message);
  }
}

export async function disconnectPrisma(): Promise<void> {
  await prisma.$disconnect();
}
