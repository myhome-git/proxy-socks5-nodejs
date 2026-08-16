# 部署指南

## 前置条件

- Node.js（服务器已安装）
- 已安装 npm 依赖：`npm install`
- 已编译：`npm run build`（生成 `dist/index.js`）

## 服务管理

### 注册服务（首次部署）

在项目目录下执行，自动取当前路径作为工作目录：

```bash
npm run service-register
```

### 启动

```bash
npm run service-start
```

### 停止

```bash
npm run service-stop
```

### 重载（改完 `.env.dev` 或源码后）

```bash
# 如果改过源码，先编译
npm run build

# 重载服务
npm run service-reload
```

### 查看日志

```bash
journalctl -u proxy-tcp.service -f
```

### 移除服务

```bash
npm run service-remove
```

## 部署流程

### 首次部署

```bash
# 1. 编译
npm run build

# 2. 注册服务
npm run service-register

# 3. 启动
npm run service-start

# 4. 确认运行状态
systemctl status proxy-tcp.service
```

### 更新部署

```bash
# 1. 拉取最新代码 / 同步 dist/
git pull
# 或 scp -r dist/ root@服务器:/home/projects/proxy-bun-test/

# 2. 编译（如果改过源码）
npm run build

# 3. 重载服务
npm run service-reload
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `deploy/proxy-tcp.service` | systemd unit 模板（`{{WORK_DIR}}` 注册时自动替换） |
| `deploy/register.sh` | 注册服务 |
| `deploy/start.sh` | 启动服务 |
| `deploy/stop.sh` | 停止服务 |
| `deploy/reload.sh` | 重载服务 |
| `deploy/remove.sh` | 移除服务 |