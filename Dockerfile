# One image: builds the web app, runs the API (HTTP 5178, HTTPS + JA4 5443) with tsx.
FROM docker.io/library/node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/scoring/package.json packages/scoring/
COPY packages/collector/package.json packages/collector/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY . .
RUN npm run build
ENV NODE_ENV=production DATA_DIR=/data PORT=5178 HTTPS_PORT=5443
VOLUME /data
EXPOSE 5178 5443
# Download the IP datasets on first start, then serve.
CMD ["sh", "-c", "[ -f /data/dbip-city-lite.mmdb ] || npx tsx scripts/update-data.ts; exec npx tsx apps/api/src/server.ts"]
