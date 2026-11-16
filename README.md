# Central Identity Provider (IdP) REST API

A production-grade, 100% cloud-hosted Central Identity Provider (IdP) REST API built with **Node.js**, **Fastify**, and **TypeScript**. Designed as a high-security, low-latency, cross-platform authentication backend for modern games and applications (**Unreal Engine 5**, **Unity**, **Godot 4**, Web, and Mobile).

---

## Architecture & Security Highlights

- **Cryptographic Asymmetric Tokens (RS256 via `jose`):** Access Tokens are signed with an RSA-2048 private key. Client game servers and microservices verify player JWTs completely offline using public keys exposed at `/.well-known/jwks.json`, placing zero read load on the IdP database.
- **Refresh Token Rotation & Automatic Reuse Detection:** Refresh tokens are 48-byte cryptographically secure random strings, stored as SHA-256 hashes in PostgreSQL. In accordance with OAuth 2.0 Security Best Current Practice (BCP), attempting to reuse an already-revoked refresh token triggers an immediate global session revocation for that user.
- **Argon2id Password Hashing:** Utilizes the RFC 9106 recommended profile (`m=65536, t=3, p=4`), providing maximum resistance to GPU/ASIC cracking attacks.
- **Encrypted Secrets At Rest (AES-256-GCM):** TOTP secrets are encrypted with AES-256-GCM using authenticated encryption tags and random 96-bit initialization vectors before storage in PostgreSQL.
- **Multi-Factor Authentication (2FA) & Passkeys:** Native support for Authenticator Apps (TOTP via `otplib`) and WebAuthn / Passkeys (biometric TouchID/FaceID/YubiKey via `@simplewebauthn/server`).
- **Distributed Rate Limiting (Upstash Redis):** Sliding/fixed window limits enforced via atomic Redis operations:
  - Max 5 failed login attempts per 15 minutes per IP and username.
  - Max 3 OTP requests per 10 minutes per email or phone number.
  - Max 5 OTP verification attempts before automatic code invalidation and lockout.
- **Security-First Observability:** Fastify logger configured with strict redaction paths for passwords, OTP codes, session tokens, TOTP secrets, and admin keys.
- **Enterprise Defenses:** `@fastify/helmet` (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and configurable CORS.

---

## Directory Structure

```
central-idp-api/
├── .env.example              # Environment variables template
├── Dockerfile                # Multi-stage production container
├── render.yaml               # Render Infrastructure as Code
├── package.json              # Exact dependencies and scripts
├── tsconfig.json             # Strict TypeScript configuration
├── prisma/
│   ├── schema.prisma         # Prisma ORM schema
│   └── migrations/
│       └── 0_init/
│           └── migration.sql # Exact PostgreSQL migration script
├── scripts/
│   └── generate-keys.ts      # RS256 RSA keypair and secret generator
├── src/
│   ├── config/
│   │   ├── env.ts            # Zod-validated environment config
│   │   └── constants.ts      # App TTLs, rate limit parameters, and constants
│   ├── database/
│   │   ├── prisma.ts         # Prisma client with connection lifecycle
│   │   └── redis.ts          # Upstash Redis client with retry strategies
│   ├── services/
│   │   ├── crypto.service.ts # Argon2id, AES-256-GCM, SHA-256, timingSafeEqual
│   │   ├── token.service.ts  # RS256 JWT, JWKS exporter, refresh token rotation
│   │   ├── otp.service.ts    # 6-digit OTP generation, SHA-256 Redis storage
│   │   ├── rate-limit.service.ts # Redis-backed rate limiting logic
│   │   ├── email.service.ts  # Resend SDK client & responsive templates
│   │   ├── sms/              # Pluggable SMS architecture (Twilio / MSG91)
│   │   │   ├── sms.interface.ts
│   │   │   ├── twilio.provider.ts
│   │   │   └── index.ts
│   │   ├── totp.service.ts   # otplib TOTP setup and verify
│   │   └── webauthn.service.ts # @simplewebauthn/server passkey implementation
│   ├── middleware/
│   │   ├── auth.middleware.ts  # Bearer JWT verification hook
│   │   └── admin.middleware.ts # x-admin-api-key guard hook
│   ├── schemas/              # Zod validation schemas
│   ├── routes/               # Modular Fastify route controllers
│   ├── plugins/              # Error handler and redacted Pino logger
│   ├── app.ts                # App initialization & plugin registration
│   └── server.ts             # Entry point with graceful shutdown
└── tests/                    # Unit and integration test suites
```

---

## Database Setup (Neon PostgreSQL)

### Option A: Prisma ORM
```bash
# Push schema to your Neon database
npm run prisma:push

# Generate Prisma Client
npm run prisma:generate
```

### Option B: Raw SQL Migration
Execute the file located at [`prisma/migrations/0_init/migration.sql`](file:///C:/Users/NVSR%20REDDY/.gemini/antigravity/scratch/central-idp-api/prisma/migrations/0_init/migration.sql) inside Neon's SQL Console.

---

## Game Engine Offline JWT Verification

Game servers (Unreal Engine Dedicated Server, Unity Mirror/Netcode, Godot High-Level Multiplayer) can verify player identity offline by caching the public key from `GET /.well-known/jwks.json`.

### Unity C# Example (using `System.IdentityModel.Tokens.Jwt`)
```csharp
using System;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

public class GameAuthVerifier {
    public static async System.Threading.Tasks.Task<bool> VerifyPlayerToken(string jwtToken, string jwksUrl) {
        using var client = new HttpClient();
        string jwksJson = await client.GetStringAsync(jwksUrl);
        var jwks = new JsonWebKeySet(jwksJson);

        var parameters = new TokenValidationParameters {
            ValidIssuer = "https://auth.yourdomain.com",
            ValidAudience = "central-idp-clients",
            IssuerSigningKeys = jwks.Keys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        var handler = new JwtSecurityTokenHandler();
        try {
            var principal = handler.ValidateToken(jwtToken, parameters, out _);
            return principal.Identity.IsAuthenticated;
        } catch {
            return false;
        }
    }
}
```

### Unreal Engine C++ Example
In Unreal Engine, use the built-in HTTP module to fetch `/.well-known/jwks.json` on dedicated server startup, parse the RSA modulus (`n`) and exponent (`e`) using OpenSSL (shipped with UE), and verify the incoming player access token during `AGameModeBase::PreLogin`.

---

## Deployment Guide: Neon, Upstash, Resend & Render

### Step 1: Database Setup (Neon)
1. Go to [Neon.tech](https://neon.tech) and create a new project.
2. Under **Connection Details**, select **Node.js** and copy the connection string.
3. It will look like:
   `postgresql://username:password@ep-dry-leaf-123456.us-east-2.aws.neon.tech/neondb?sslmode=require`

### Step 2: Redis Setup (Upstash)
1. Go to [Upstash.com](https://upstash.com) and create a Redis database.
2. Choose your preferred cloud region (e.g. AWS / us-east-1).
3. Under the database details, copy the `ioredis` connection URL (`rediss://...`).

### Step 3: Transactional Email Setup (Resend)
1. Go to [Resend.com](https://resend.com) and create an API Key.
2. Add and verify your sending domain (e.g., `auth.yourdomain.com`).
3. Set `RESEND_FROM_EMAIL="noreply@auth.yourdomain.com"`.

### Step 4: Generate Production Keys
Run the included key generator script:
```bash
npm run generate:keys
```
This generates:
- An RS256 RSA-2048 Key Pair in PEM format.
- A 32-byte hex key for AES-256-GCM encryption (`ENCRYPTION_KEY`).
- A high-entropy `ADMIN_API_KEY`.
- A unique `JWT_KEY_ID`.

### Step 5: One-Click Deploy to Render
1. Push this repository to GitHub or GitLab.
2. In [Render Dashboard](https://dashboard.render.com), click **New +** -> **Blueprint**.
3. Connect your repository. Render will automatically detect [`render.yaml`](file:///C:/Users/NVSR%20REDDY/.gemini/antigravity/scratch/central-idp-api/render.yaml).
4. Fill in the prompted secret environment variables:
   - `DATABASE_URL`: Your Neon PostgreSQL connection string.
   - `REDIS_URL`: Your Upstash Redis URL.
   - `JWT_KEY_ID`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`: From `npm run generate:keys`.
   - `ENCRYPTION_KEY`: 64-character hex key from `npm run generate:keys`.
   - `ADMIN_API_KEY`: High-entropy secret.
   - `RESEND_API_KEY`: Key from Resend.
5. Click **Apply**. Render will automatically build the multi-stage Docker image, verify `/health`, and bring your Central IdP live!
