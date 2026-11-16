import { Redis } from 'ioredis';
import { config } from '../config/env.js';

export const redis = new Redis(config.REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: true,
  retryStrategy(times) {
    // Exponential backoff with a cap of 3000ms
    const delay = Math.min(times * 100, 3000);
    return delay;
  },
  reconnectOnError(err) {
    const targetError = 'READONLY';
    if (err.message.includes(targetError)) {
      return true; // Reconnect when cluster or failover happens
    }
    return false;
  },
});

redis.on('error', (err) => {
  // Upstash cold starts or network hiccups logged as warning
  console.warn('Redis connection event:', err.message);
});

redis.on('connect', () => {
  if (config.NODE_ENV === 'development') {
    console.log('Redis client connected successfully.');
  }
});

export async function connectRedis(): Promise<void> {
  try {
    await redis.connect();
  } catch (error) {
    console.warn('Redis initial connection deferred:', (error as Error).message);
  }
}

export async function disconnectRedis(): Promise<void> {
  try {
    await redis.quit();
  } catch {
    redis.disconnect();
  }
}
