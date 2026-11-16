-- Create UUID and crypto extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Table: users
CREATE TABLE IF NOT EXISTS "users" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" VARCHAR(50) NOT NULL UNIQUE,
    "password_hash" TEXT NOT NULL,
    "email" VARCHAR(255) UNIQUE,
    "email_verified" BOOLEAN NOT NULL DEFAULT false,
    "phone_number" VARCHAR(32) UNIQUE,
    "phone_verified" BOOLEAN NOT NULL DEFAULT false,
    "totp_secret_encrypted" TEXT,
    "totp_enabled" BOOLEAN NOT NULL DEFAULT false,
    "marketing_opt_in" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "check_email_or_phone" CHECK (
        "email" IS NOT NULL OR "phone_number" IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS "users_username_idx" ON "users" ("username");

-- Table: refresh_tokens
CREATE TABLE IF NOT EXISTS "refresh_tokens" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
    "token_hash" TEXT NOT NULL,
    "device_fingerprint" TEXT,
    "ip_address" VARCHAR(45),
    "expires_at" TIMESTAMP(6) NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS "refresh_tokens_user_id_idx" ON "refresh_tokens" ("user_id");
CREATE INDEX IF NOT EXISTS "refresh_tokens_token_hash_idx" ON "refresh_tokens" ("token_hash");

-- Table: webauthn_credentials
CREATE TABLE IF NOT EXISTS "webauthn_credentials" (
    "id" TEXT PRIMARY KEY,
    "user_id" UUID NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
    "public_key" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT[] NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS "webauthn_credentials_user_id_idx" ON "webauthn_credentials" ("user_id");
