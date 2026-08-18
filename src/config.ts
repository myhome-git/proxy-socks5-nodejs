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
    log(`⚠ 未找到 .env 文件: ${path}，所有配置必须通过环境变量提供`, "WARN");
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

  // 监听地址
  bindHost: string;

  // SOCKS5 代理端口
  socks5Port: number;

  // HTTP 代理端口（方案B，与 SOCKS5 分开监听）
  httpProxyPort: number;

  // ===== 加密隧道配置 (Mode1 ↔ Mode2) =====
  // 加密密码（用于派生 AES-256 密钥）
  encryptPassword: string;
  // 加密盐值
  encryptSalt: string;
  // 调试日志开关
  debugLog: boolean;
  // Mode1 连接 Mode2 的协议（ws 或 wss）
  remoteProtocol: "ws" | "wss";
  // Mode1 连接 Mode2 的地址（Mode1 用）
  remoteHost: string;
  // Mode1 连接 Mode2 的端口（Mode1 用）
  remotePort: number;
  // Mode2 监听端口（Mode2 用）
  encryptListenPort: number;
  // Mode2 监听地址（Mode2 用）
  encryptListenHost: string;

}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`❌ 缺少必要环境变量: ${name}，请在 .env.dev 文件中配置`);
  }
  return value;
}

export function loadConfig(): AppConfig {
  const config: AppConfig = {
    proxyMode: requireEnv("PROXY_MODE") as "mode1" | "mode2",
    bindHost: requireEnv("BIND_HOST"),
    socks5Port: parseInt(requireEnv("SOCKS5_PORT"), 10),
    httpProxyPort: parseInt(requireEnv("HTTP_PROXY_PORT"), 10),
    encryptPassword: requireEnv("ENCRYPT_PASSWORD"),
    encryptSalt: requireEnv("ENCRYPT_SALT"),
    debugLog: process.env.DEBUG_LOG === "true",
    remoteProtocol: requireEnv("REMOTE_PROTOCOL") as "ws" | "wss",
    remoteHost: requireEnv("REMOTE_HOST"),
    remotePort: parseInt(requireEnv("REMOTE_PORT"), 10),
    encryptListenPort: parseInt(requireEnv("ENCRYPT_LISTEN_PORT"), 10),
    encryptListenHost: requireEnv("ENCRYPT_LISTEN_HOST"),
  };

  return config;
}

/**
 * 返回手动配置的 WebSocket 协议
 */
export function resolveWsProtocol(config: AppConfig): "ws" | "wss" {
  return config.remoteProtocol;
}

export function printConfig(config: AppConfig) {
  const wsProto = resolveWsProtocol(config);
  log("============================================");
  log(`代理配置 (模式: ${config.proxyMode})`);
  
  if (config.proxyMode === "mode1") {
    log(`  SOCKS5 代理:   ${config.bindHost}:${config.socks5Port}`);
    log(`  HTTP 代理:     ${config.bindHost}:${config.httpProxyPort}`);
    log(`  加密隧道:      → ${wsProto}://${config.remoteHost}:${config.remotePort}`);
    log(`  协议检测:      HTTPS / HTTP / WebSocket / TCP (统一隧道)`);
  } else {
    log(`  WebSocket 隧道: ${wsProto}://${config.encryptListenHost}:${config.encryptListenPort}/tunnel`);
  }
  log("============================================");
}
