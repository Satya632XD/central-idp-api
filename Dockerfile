# ==========================================
# Stage 1: Build & Compilation
# ==========================================
FROM node:22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package manifests
COPY package*.json tsconfig.json ./
COPY prisma ./prisma/

# Install all dependencies including devDependencies for build
RUN npm ci

# Generate Prisma Client
RUN npx prisma generate

# Copy source code and build scripts
COPY src ./src
COPY scripts ./scripts

# Build TypeScript to Javascript (dist/)
RUN npm run build

# Remove development dependencies to keep final image slim
RUN npm prune --omit=dev

# ==========================================
# Stage 2: Production Runtime
# ==========================================
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Install dumb-init for proper PID 1 signal forwarding
RUN apk add --no-cache dumb-init

# Copy production artifacts from builder
COPY --chown=node:node package*.json ./
COPY --chown=node:node prisma ./prisma
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist

# Security hardening: Run as unprivileged user
USER node

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

EXPOSE 3000

# Start with dumb-init to handle SIGINT/SIGTERM cleanly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/src/server.js"]
