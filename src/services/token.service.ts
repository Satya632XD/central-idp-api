import {
  importPKCS8,
  importSPKI,
  SignJWT,
  jwtVerify,
  exportJWK,
  JWK,
} from 'jose';
import { config } from '../config/env.js';
import { CONSTANTS } from '../config/constants.js';
import { CryptoService } from './crypto.service.js';
import { prisma } from '../database/prisma.js';
import { AuthTokens, JwtUserPayload } from '../types/index.js';

export class TokenService {
  private static privateKey: CryptoKey | null = null;
  private static publicKey: CryptoKey | null = null;
  private static cachedJwk: JWK | null = null;

  private static async getPrivateKey(): Promise<CryptoKey> {
    if (!this.privateKey) {
      this.privateKey = (await importPKCS8(config.JWT_PRIVATE_KEY, 'RS256')) as CryptoKey;
    }
    return this.privateKey;
  }

  private static async getPublicKey(): Promise<CryptoKey> {
    if (!this.publicKey) {
      this.publicKey = (await importSPKI(config.JWT_PUBLIC_KEY, 'RS256')) as CryptoKey;
    }
    return this.publicKey;
  }

  /**
   * Generates an RS256 asymmetric Access Token (15m expiry).
   */
  static async generateAccessToken(payload: {
    userId: string;
    username: string;
    email?: string | null;
    phone_number?: string | null;
  }): Promise<string> {
    const key = await this.getPrivateKey();

    return new SignJWT({
      username: payload.username,
      email: payload.email,
      phone_number: payload.phone_number,
      type: 'access',
    })
      .setProtectedHeader({ alg: 'RS256', kid: config.JWT_KEY_ID })
      .setSubject(payload.userId)
      .setIssuer(config.JWT_ISSUER)
      .setAudience(config.JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${CONSTANTS.ACCESS_TOKEN_TTL_SECONDS}s`)
      .sign(key);
  }

  /**
   * Generates a short-lived temporary token for completing 2FA login (5m expiry).
   */
  static async generate2FaPendingToken(
    userId: string,
    identifier: string
  ): Promise<string> {
    const key = await this.getPrivateKey();

    return new SignJWT({
      identifier,
      type: '2fa_pending',
    })
      .setProtectedHeader({ alg: 'RS256', kid: config.JWT_KEY_ID })
      .setSubject(userId)
      .setIssuer(config.JWT_ISSUER)
      .setAudience(config.JWT_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(`${CONSTANTS.TWO_FACTOR_TEMP_TOKEN_TTL_SECONDS}s`)
      .sign(key);
  }

  /**
   * Verifies an RS256 Access Token.
   */
  static async verifyAccessToken(token: string): Promise<JwtUserPayload> {
    const key = await this.getPublicKey();
    const { payload } = await jwtVerify(token, key, {
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });

    if (payload.type !== 'access') {
      throw new Error('Invalid token type');
    }

    return {
      sub: payload.sub as string,
      username: payload.username as string,
      email: payload.email as string | undefined,
      phone_number: payload.phone_number as string | undefined,
      type: 'access',
    };
  }

  /**
   * Verifies a temporary 2FA token.
   */
  static async verify2FaPendingToken(token: string): Promise<{
    userId: string;
    identifier: string;
  }> {
    const key = await this.getPublicKey();
    const { payload } = await jwtVerify(token, key, {
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });

    if (payload.type !== '2fa_pending' || !payload.sub) {
      throw new Error('Invalid or expired 2FA verification token');
    }

    return {
      userId: payload.sub,
      identifier: (payload.identifier as string) || '',
    };
  }

  /**
   * Creates and stores a new hashed Refresh Token (30d expiry) in PostgreSQL.
   */
  static async createRefreshToken(
    userId: string,
    ipAddress?: string,
    deviceFingerprint?: string
  ): Promise<string> {
    const rawToken = CryptoService.generateRandomToken(48);
    const tokenHash = CryptoService.sha256(rawToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + CONSTANTS.REFRESH_TOKEN_TTL_DAYS);

    await prisma.refreshToken.create({
      data: {
        user_id: userId,
        token_hash: tokenHash,
        ip_address: ipAddress || null,
        device_fingerprint: deviceFingerprint || null,
        expires_at: expiresAt,
        revoked: false,
      },
    });

    return rawToken;
  }

  /**
   * Rotates a refresh token securely with Automatic Token Reuse Detection.
   * If a revoked token is reused, all tokens for the user are immediately revoked!
   */
  static async rotateRefreshToken(
    rawRefreshToken: string,
    ipAddress?: string,
    deviceFingerprint?: string
  ): Promise<AuthTokens> {
    const tokenHash = CryptoService.sha256(rawRefreshToken);

    const existingToken = await prisma.refreshToken.findFirst({
      where: { token_hash: tokenHash },
      include: { user: true },
    });

    if (!existingToken) {
      throw new Error('Invalid refresh token');
    }

    // CRITICAL: Token Reuse Detection
    if (existingToken.revoked) {
      // Possible token compromise! Invalidate ALL sessions for this user.
      await prisma.refreshToken.updateMany({
        where: { user_id: existingToken.user_id },
        data: { revoked: true },
      });

      throw new Error(
        'Token reuse detected. Potential compromise. All active sessions have been revoked.'
      );
    }

    // Check expiration
    if (existingToken.expires_at.getTime() < Date.now()) {
      throw new Error('Refresh token has expired');
    }

    // Invalidate the current refresh token
    await prisma.refreshToken.update({
      where: { id: existingToken.id },
      data: { revoked: true },
    });

    // Create a new rotated refresh token
    const newRefreshToken = await this.createRefreshToken(
      existingToken.user_id,
      ipAddress,
      deviceFingerprint
    );

    // Issue new RS256 access token
    const newAccessToken = await this.generateAccessToken({
      userId: existingToken.user.id,
      username: existingToken.user.username,
      email: existingToken.user.email,
      phone_number: existingToken.user.phone_number,
    });

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: CONSTANTS.ACCESS_TOKEN_TTL_SECONDS,
    };
  }

  /**
   * Revokes a single refresh token (used for single-device logout).
   */
  static async revokeRefreshToken(rawRefreshToken: string): Promise<boolean> {
    const tokenHash = CryptoService.sha256(rawRefreshToken);
    const result = await prisma.refreshToken.updateMany({
      where: { token_hash: tokenHash, revoked: false },
      data: { revoked: true },
    });
    return result.count > 0;
  }

  /**
   * Revokes all active sessions for a user (global logout / security revoke).
   */
  static async revokeAllUserSessions(userId: string): Promise<number> {
    const result = await prisma.refreshToken.updateMany({
      where: { user_id: userId, revoked: false },
      data: { revoked: true },
    });
    return result.count;
  }

  /**
   * Exports the public key as a standard JWKS (JSON Web Key Set).
   * Offline game servers (Unreal, Unity, Godot) consume this at `/.well-known/jwks.json`.
   */
  static async exportJwks(): Promise<{ keys: JWK[] }> {
    if (!this.cachedJwk) {
      const pubKey = await this.getPublicKey();
      const jwk = await exportJWK(pubKey);
      this.cachedJwk = {
        ...jwk,
        kid: config.JWT_KEY_ID,
        use: 'sig',
        alg: 'RS256',
      };
    }
    return { keys: [this.cachedJwk] };
  }
}
