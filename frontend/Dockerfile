# =========================================================
# SecurePatch AI Security Platform - Frontend Dockerfile
# Multi-stage production build (Node.js -> Nginx Alpine)
# =========================================================

# Stage 1: Build the React + Vite static bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency specifications first for Docker layer caching
COPY package*.json ./
RUN npm install

# Copy application source and build production artifacts
COPY . .
RUN npm run build

# Stage 2: Serve with lightweight Nginx Alpine
FROM nginx:alpine

# Copy built static assets from Stage 1
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration with SPA routing support
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
