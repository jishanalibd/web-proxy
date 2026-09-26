FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production --no-audit --no-fund

COPY server.js ./

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
