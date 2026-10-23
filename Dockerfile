FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package*.json ./
COPY src ./src
COPY server.js ./
RUN addgroup -S app && adduser -S app -G app \
 && mkdir -p /app/data && chown -R app:app /app
USER app
ENV DB_PATH=/app/data/database.db
EXPOSE 3030
CMD ["node", "server.js"]