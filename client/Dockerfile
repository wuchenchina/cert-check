# Build stage
FROM node:20-alpine as build

# 构建时代理设置
ARG HTTP_PROXY=http://10.0.0.1:7890
ARG HTTPS_PROXY=http://10.0.0.1:7890
ENV http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY

WORKDIR /app

COPY package.json yarn.lock* ./

RUN yarn install

COPY . .

RUN yarn build

# Production stage
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
