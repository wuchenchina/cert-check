# SSL Certificate Checker

一个用于查看指定网址 SSL 证书详细信息的工具，支持查看完整证书链和自签名证书。

## 技术栈

- **前端**: Vite + React + Ant Design
- **后端**: Node.js + Express
- **部署**: Docker Compose

## 快速开始

### 使用 Docker Compose（推荐）

```bash
# 复制环境配置
cp .env.example .env

# 按需修改端口等配置
vim .env

# 构建并启动
docker-compose up -d --build
```

访问 http://localhost:3000（或你配置的端口）

#### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `FRONTEND_PORT` | 3000 | 前端服务端口 |
| `BACKEND_PORT` | 3001 | 后端 API 端口 |
| `TZ` | Asia/Shanghai | 时区 |

#### 数据持久化

| 卷名 | 容器路径 | 说明 |
|------|----------|------|
| `certcheck-logs` | `/app/logs` | 日志文件 |
| `certcheck-cache` | `/app/cache` | 缓存数据 |

### 本地开发

#### 启动后端

```bash
cd server
yarn install
yarn dev
```

#### 启动前端

```bash
cd client
yarn install
yarn dev
```

## 功能特性

- 🔐 查看任意域名的 SSL 证书信息
- 🔗 显示完整的证书链
- ✅ 支持自签名证书
- 🇨🇳 **支持国密证书 (SM2/SM3/SM4)**
- 🛡️ 识别 DV/OV/EV 证书类型
- ⚡ 识别 RSA/ECC/国密 公钥算法
- 🎨 现代化的 UI 设计
- 📱 响应式布局

## 国密支持

Docker 镜像内置 **Tongsuo（铜锁）**——阿里巴巴开源的国密 OpenSSL 分支，支持：

- **SM2** - 国密椭圆曲线公钥密码算法
- **SM3** - 国密杂凑算法
- **SM4** - 国密分组密码算法
- **NTLS** - 国密 TLS 协议

当 Node.js 原生 TLS 无法连接时，会自动回退到 Tongsuo 获取国密证书。

## API 接口

### GET /api/certificate?domain={domain}

获取指定域名的 SSL 证书信息。

**参数**:
- `domain`: 要查询的域名（不包含协议前缀）
- `port`: 端口号（可选，默认 443）

**返回示例**:
```json
{
  "success": true,
  "data": {
    "certificates": [...],
    "isValid": true,
    "domain": "example.com"
  }
}
```
