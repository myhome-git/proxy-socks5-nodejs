# 🚀 加密隧道代理 (Encrypted Tunnel Proxy)

基于 **Node.js** 的 **HTTP 代理 + SOCKS5 代理**，支持加密隧道转发。

## 架构

```
客户端 ──→ Mode1 (本地加密代理) ──加密隧道──→ Mode2 (远程解密转发) ──→ 目标服务器
                │                                                          │
                ├── HTTP 代理 (9090) ──────────────────────────────────→ 普通 HTTP 转发
                └── SOCKS5 代理 (1080) ────────────────────────────────→ TCP 隧道转发
```

## 快速开始

```bash
npm install
npm start
```

## 使用方式

### HTTP 代理

```bash
curl -x http://127.0.0.1:9090 http://example.com
```

### SOCKS5 代理

```bash
curl --socks5 127.0.0.1:1080 http://example.com
curl --socks5 127.0.0.1:1080 https://example.com
```

### 浏览器/系统代理设置

| 协议 | 地址 | 端口 |
|------|------|------|
| HTTP | 127.0.0.1 | 9090 |
| SOCKS5 | 127.0.0.1 | 1080 |


