/**
 * 配置模块
 *
 * 从 .env.dev 文件加载配置到 process.env，提供统一的配置访问接口。
 * 使用 fs 模块替代 dotenv，减少外部依赖。
 */
import fs from "fs";
import { log } from "./utils.js";

/**
 * 简易 .env 文件解析器，将键值对注入 process.env。
 * 支持：
 *   - 注释行（以 # 开头）
 *   - 空行跳过
 *   - KEY=VALUE 格式（等号两侧空格可选的）
 *   - 引号包裹的值（单引号/双引号）
 */
function loadEnvFile(path: string): void {
  let content: string;
  try {
    content = fs.readFileSync(path, "utf-8");
  } catch {
    log(`⚠ 未找到 .env 文件: ${path}，使用默认配置`, "WARN");
    return;
  }

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) continue;

    const key = line.slice(0, eqIdx).trim();
    let value = line.slice(eqIdx + 1).trim();

    // 去除包裹的引号
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    if (key && !(key in process.env)) {
      process.env[key] = value;
    }
  }

  log(`已加载 .env 文件: ${path}`, "INFO");
}

// 加载 .env.dev 配置文件（与 Bun 版保持一致）
loadEnvFile(".env.dev");

export interface AppConfig {
  // 运行模式: "mode1" = 加密端(本地), "mode2" = 解密端(远程)
  proxyMode: "mode1" | "mode2";

  // 统一监听地址（HTTP 与 SOCKS5 共用）
  bindHost: string;

  // HTTP 代理
  httpPort: number;

  // SOCKS5 代理
  socks5Port: number;

  // ===== 加密隧道配置 (Mode1 ↔ Mode2) =====
  // 加密密码（用于派生 AES-256 密钥）
  encryptPassword: string;
  // 加密盐值
  encryptSalt: string;
  // Mode1 连接 Mode2 的地址（Mode1 用）
  remoteHost: string;
  // Mode1 连接 Mode2 的端口（Mode1 用）
  remotePort: number;
  // Mode2 监听端口（Mode2 用）
  encryptListenPort: number;
  // Mode2 监听地址（Mode2 用）
  encryptListenHost: string;
}

export function loadConfig(): AppConfig {
  const config: AppConfig = {
    proxyMode: (process.env.PROXY_MODE || "mode1") as "mode1" | "mode2",

    bindHost: process.env.BIND_HOST || "0.0.0.0",

    httpPort: parseInt(process.env.HTTP_PORT || "9090", 10),

    socks5Port: parseInt(process.env.SOCKS5_PORT || "1080", 10),

    // 加密隧道配置
    encryptPassword: process.env.ENCRYPT_PASSWORD || "default-encrypt-key-2024",
    encryptSalt: process.env.ENCRYPT_SALT || "proxy-salt",
    remoteHost: process.env.REMOTE_HOST || "127.0.0.1",
    remotePort: parseInt(process.env.REMOTE_PORT || "9999", 10),
    encryptListenPort: parseInt(process.env.ENCRYPT_LISTEN_PORT || "9999", 10),
    encryptListenHost: process.env.ENCRYPT_LISTEN_HOST || "0.0.0.0",
  };

  log(`配置加载完成: 模式=${config.proxyMode}, HTTP=${config.bindHost}:${config.httpPort}, SOCKS5=${config.bindHost}:${config.socks5Port}`);
  return config;
}

export function printConfig(config: AppConfig) {
  log("============================================");
  log(`代理配置 (模式: ${config.proxyMode})`);
  log(`  HTTP 代理:     ${config.bindHost}:${config.httpPort}`);
  log(`  SOCKS5 代理:   ${config.bindHost}:${config.socks5Port}`);
  
  if (config.proxyMode === "mode1") {
    log(`  加密隧道:      → ${config.remoteHost}:${config.remotePort}`);
  } else {
    log(`  加密监听:      ${config.encryptListenHost}:${config.encryptListenPort}`);
  }
  log("============================================");
}