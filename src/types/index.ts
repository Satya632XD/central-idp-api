import { FastifyRequest } from 'fastify';

export interface JwtUserPayload {
  sub: string;
  username: string;
  email?: string | null;
  phone_number?: string | null;
  type?: 'access' | '2fa_pending';
  [key: string]: unknown;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: JwtUserPayload;
  }
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
}

export interface UserResponse {
  id: string;
  username: string;
  email: string | null;
  email_verified: boolean;
  phone_number: string | null;
  phone_verified: boolean;
  totp_enabled: boolean;
  marketing_opt_in: boolean;
  created_at: Date;
}
