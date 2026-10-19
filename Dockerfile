FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src ./src
COPY public ./public
RUN mkdir /app/.runtime && chown -R node:node /app
USER node
EXPOSE 7000
CMD ["node", "src/launch-local.js"]
