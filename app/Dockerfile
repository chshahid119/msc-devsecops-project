# Stage 1: Build & test
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm test

# Stage 2: Production
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app .
ENV APP_VERSION=1.0.0
EXPOSE 3000
CMD ["npm", "start"]
