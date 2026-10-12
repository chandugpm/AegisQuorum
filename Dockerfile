FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
RUN mkdir /app/.runtime && chown -R node:node /app
USER node
EXPOSE 7000
CMD ["node", "src/launch-local.js"]
