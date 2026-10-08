FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:24-alpine
WORKDIR /app
COPY --from=build /app/build ./build
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "build/index.js"]
