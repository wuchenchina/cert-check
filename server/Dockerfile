# 多阶段构建：编译 Tongsuo（铜锁）支持国密
FROM alpine:3.19 AS tongsuo-builder

# 构建时代理设置
ARG HTTP_PROXY=http://10.0.0.1:7890
ARG HTTPS_PROXY=http://10.0.0.1:7890
ENV http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY

# 使用清华镜像源 (HTTPS)
RUN echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.19/main" > /etc/apk/repositories && \
    echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.19/community" >> /etc/apk/repositories

RUN apk update && apk add --no-cache \
    build-base \
    perl \
    linux-headers \
    git

# 克隆并编译 Tongsuo（阿里巴巴国密 OpenSSL 分支）
RUN git clone --depth 1 --branch 8.4.0 https://github.com/Tongsuo-Project/Tongsuo.git /tongsuo && \
    cd /tongsuo && \
    ./Configure \
        --prefix=/opt/tongsuo \
        --libdir=/opt/tongsuo/lib \
        enable-ntls \
        enable-ssl-trace \
        enable-ec_elgamal \
        enable-sm2 \
        enable-sm3 \
        enable-sm4 \
        no-shared && \
    make -j$(nproc) && \
    make install_sw

# 运行时镜像
FROM node:20-alpine

# 构建时代理设置
ARG HTTP_PROXY=http://10.0.0.1:7890
ARG HTTPS_PROXY=http://10.0.0.1:7890
ENV http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY

# 使用清华镜像源 (HTTPS) - node:20-alpine 基于 alpine 3.20
RUN echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.20/main" > /etc/apk/repositories && \
    echo "https://mirrors.tuna.tsinghua.edu.cn/alpine/v3.20/community" >> /etc/apk/repositories

# 安装运行时依赖
RUN apk update && apk add --no-cache libstdc++ libgcc ca-certificates

# 复制 Tongsuo
COPY --from=tongsuo-builder /opt/tongsuo /opt/tongsuo
ENV PATH="/opt/tongsuo/bin:$PATH"
ENV OPENSSL_CMD="/opt/tongsuo/bin/openssl"

WORKDIR /app

# 创建日志和缓存目录
RUN mkdir -p /app/logs /app/cache

COPY package.json yarn.lock* ./

RUN yarn install --production

# 清除代理设置（运行时不需要）
ENV http_proxy= https_proxy=

COPY . .

EXPOSE 3001

CMD ["node", "src/index.js"]
