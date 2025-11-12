# Dockerfile
FROM node:20

# Variável para definir o modo (default: development)
ARG NODE_ENV=development
ENV NODE_ENV=$NODE_ENV

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 9696

# Se estiver em dev, usamos o start:dev (hot reload)
CMD ["sh", "-c", "if [ \"$NODE_ENV\" = \"development\" ]; then npm run start:dev; else npm run start:prod; fi"]
