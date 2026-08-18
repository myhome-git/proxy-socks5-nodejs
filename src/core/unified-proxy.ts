/**
 * 统一代理服务器
 *
 * 在单个端口上同时支持 SOCKS5 和 HTTP 代理协议，
 * 并内置 WebSocket 加密隧道能力，直接连接远程 Mode2 解密端。
 *
 * 根据客户端首字节自动检测协议类型：
 *   0x05 → SOCKS5 代理
 *   其他 → HTTP 代理 (GET/POST/CONNECT)
 *
 * 浏览器流量统一通过 WebSocket 加密隧道转发到 Mode2。
 */
import net from "net";
import { WebSocket } from "ws";
import { log } from "../utils.js";
import { Socks5Server } from "./socks5.js";
import type { Tunnel, TunnelCreator } from "./socks5.js";
export type { Tunnel, TunnelCreator };
import { HttpProxyServer } from "./http-proxy.js";
import {
  pack, tryUnpack,
  packTunnelData, tryUnpackTunnelData,
  serializeTunnelRequest, parseCommand,
} from "../security/sbox.js";

/**
 * 检测代理协议类型
 * @param firstByte 客户端发送的第一个字节
 * @returns "socks5" 或 "http"
 */
function detectProxyProtocol(firstByte: number): "socks5" | "http" {
  if (firstByte === 0x05) return "socks5";
  return "http";
}

// ============================================================
// 浏览器协议检测（从 mode1-handler.ts 移入）
// ============================================================

/**
 * 协议检测结果
 */
export type DetectedProtocol = "https" | "http" | "websocket" | "tcp";

/**
 * 检测浏览器协议类型（根据数据内容，而非端口）
 */
export function detectProtocol(data: Buffer): DetectedProtocol {
  if (data.length === 0) return "tcp";

  const firstByte = data[0]!;

  // TLS ClientHello (HTTPS) — 首字节 0x16
  if (firstByte === 0x16) return "https";

  // HTTP 文本协议 — 检查常见 HTTP 方法
  const head = data.slice(0, Math.min(data.length, 128)).toString("utf-8").toLowerCase();
  if (
    head.startsWith("get ") || head.startsWith("post ") ||
    head.startsWith("put ") || head.startsWith("delete ") ||
    head.startsWith("head ") || head.startsWith("patch ") ||
    head.startsWith("options ")
  ) {
    if (head.includes("upgrade") && head.includes("websocket")) {
      return "websocket";
    }
    return "http";
  }

  if (head.startsWith("http/")) return "http";
  return "tcp";
}

/**
 * UnifiedProxyServer 配置对象
 */
export interface UnifiedProxyConfig {
  proxyPort: number;
  bindHost: string;
  remoteHost: string;
  remotePort: number;
  remoteProtocol: "ws" | "wss";
  encryptKey: Buffer;
  debugLog: boolean;
}

/**
 * 统一代理服务器
 * 在单个端口上自动检测并处理 SOCKS5 和 HTTP 代理协议，
 * 所有流量通过 WebSocket 加密隧道转发到远程 Mode2 解密端。
 */
export class UnifiedProxyServer {
  private socks5Server: Socks5Server;
  private httpProxyServer: HttpProxyServer;
  private server: net.Server | null = null;
  private sockets = new Set<net.Socket>();
  private config: UnifiedProxyConfig;

  constructor(config: UnifiedProxyConfig) {
    this.config = config;
    // 内部创建 TunnelCreator，直接使用 openWSTunnel 建立加密隧道
    const createTunnel: TunnelCreator = (
      host: string, tport: number,
      firstData: Buffer,
      onData: (data: Buffer) => void,
      onClose: () => void,
    ): Promise<Tunnel> => {
      const protocol = detectProtocol(firstData);
      log(`统一代理 [${protocol}] ${host}:${tport} (${firstData.length} bytes)`);
      return this.openWSTunnel(host, tport, firstData, onData, onClose);
    };

    this.socks5Server = new Socks5Server(createTunnel);
    this.httpProxyServer = new HttpProxyServer(createTunnel);
  }

  /**
   * 启动统一代理服务器
   */
  start(): net.Server {
    const server = net.createServer((clientSocket) => {
      this.sockets.add(clientSocket);
      clientSocket.once("close", () => this.sockets.delete(clientSocket));

      clientSocket.once("data", (firstChunk) => {
        if (firstChunk.length === 0) {
          clientSocket.end();
          return;
        }

        const firstByte = firstChunk[0]!;
        const protocol = detectProxyProtocol(firstByte);

        if (this.config.debugLog) {
          log(`统一代理: 检测到协议 ${protocol} (0x${firstByte.toString(16)})`);
        }

        if (protocol === "socks5") {
          this.socks5Server.handleSocket(clientSocket, firstChunk);
        } else {
          this.httpProxyServer.handleSocket(clientSocket, firstChunk);
        }
      });

      clientSocket.on("error", () => {
        this.sockets.delete(clientSocket);
        try { clientSocket.destroy(); } catch {}
      });
    });

    server.listen(this.config.proxyPort, this.config.bindHost, () => {
      log(`统一代理服务器已启动: ${this.config.bindHost}:${this.config.proxyPort} (SOCKS5 + HTTP)`);
    });

    this.server = server;
    return server;
  }

  /**
   * 停止服务器
   */
  async stop(): Promise<void> {
    if (!this.server) return;

    for (const socket of this.sockets) {
      try { socket.destroy(); } catch {}
    }
    this.sockets.clear();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
        this.server.unref();
      } else {
        resolve();
      }
    });
  }

  // ============================================================
  // WebSocket 加密隧道（从 mode1-handler.ts 移入）
  // ============================================================

  /**
   * 通过 WebSocket 连接远程 Mode2 建立加密隧道
   */
  private openWSTunnel(
    host: string, port: number,
    firstData: Buffer,
    onData: (data: Buffer) => void,
    onClose: () => void,
  ): Promise<Tunnel> {
    const wsUrl = `${this.config.remoteProtocol}://${this.config.remoteHost}:${this.config.remotePort}/tunnel`;

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      let established = false;
      let closed = false;
      const pendingData: Buffer[] = [];

      const safeClose = () => {
        if (closed) return;
        closed = true;
        try { ws.close(); } catch {}
      };

      ws.on("open", () => {
        const tunnelCmd = serializeTunnelRequest(host, port);
        const encrypted = pack(tunnelCmd, this.config.encryptKey);
        ws.send(encrypted);

        for (const d of pendingData) {
          const encryptedData = packTunnelData(d, this.config.encryptKey);
          ws.send(encryptedData);
        }
        pendingData.length = 0;
      });

      ws.on("message", (data) => {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);

        if (!established) {
          const result = tryUnpack(buf, this.config.encryptKey);
          if (result) {
            try {
              const cmd = parseCommand(result.data);
              if (cmd.type === "tunnel_ok") {
                established = true;
                log(`WebSocket 隧道 ${host}:${port} 建立成功`);

                if (firstData.length > 0) {
                  const encryptedFirst = packTunnelData(firstData, this.config.encryptKey);
                  ws.send(encryptedFirst);
                }

                const tunnel: Tunnel = {
                  write: (d: Buffer) => {
                    if (closed) return;
                    const encryptedData = packTunnelData(d, this.config.encryptKey);
                    try { ws.send(encryptedData); } catch {}
                  },
                  close: () => {
                    safeClose();
                    onClose();
                  },
                };

                resolve(tunnel);
                return;
              }
            } catch {}
          }
        }

        if (established) {
          const result = tryUnpackTunnelData(buf, this.config.encryptKey);
          if (result) {
            if (this.config.debugLog) {
              log(`隧道响应内容 ${host}:${port} 解密（bytes）: ${result.data.length}`);
            }
            onData(result.data);
          }
        }
      });

      ws.on("close", () => {
        if (!closed) {
          closed = true;
          onClose();
        }
      });

      ws.on("error", (err) => {
        if (!closed) {
          closed = true;
          log(`WebSocket 连接错误: ${err.message}`, "ERROR");
          onClose();
          reject(err);
        }
      });

      // 超时处理
      setTimeout(() => {
        if (!established && !closed) {
          closed = true;
          log(`WebSocket 隧道建立超时: ${host}:${port}`, "WARN");
          ws.close();
          onClose();
          reject(new Error("Tunnel establishment timeout"));
        }
      }, 30000);
    });
  }
}