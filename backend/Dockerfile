FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer caching)
COPY package.json .
RUN npm install --omit=dev

# Copy source
COPY server.js .

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO /dev/null http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "server.js"]
