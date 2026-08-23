FROM node:20-alpine

RUN apk add --no-cache python3 make g++ gcc su-exec

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

RUN mkdir -p /app/data && chown -R node:node /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Nessun "USER node" qui: il container deve avviarsi come root per poter sistemare
# i permessi sul volume dati montato dall'host (vedi entrypoint.sh). L'entrypoint
# passa i privilegi all'utente "node" prima di eseguire l'app: il processo Node
# non gira mai come root.

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "server.js"]
