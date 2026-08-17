/**
 * Mode1 加密端实现
 *
 * 仅 SOCKS5 入口，接收 Proxifier 转发的所有流量。
 * 收到浏览器第一批数据后检测协议类型，统一通过 WebSocket 加密隧道转发到 Mode2。
 */
import net from "net";
import { WebSocket } from "ws";
import { Socks5Server, type Tunnel } from "../core/socks5.js";
import { log } from "../utils.js";
import { type AppConfig, resolveWsProtocol } from "../config.js";


import {
  pack,
  tryUnpack,
  packTunnelData,
  tryUnpackTunnelData,
  serializeTunnelRequest,
  parseCommand,
} from "../security/sbox.js";

/**
 * 协议检测结果
 */
export type DetectedProtocol = "https" | "http" | "websocket" | "tcp";

/**
 * 检测浏览器协议类型（根据数据内容，而非端口）
 */
function detectProtocol(data: Buffer): DetectedProtocol {
  if (data.length === 0) return "tcp";

  const firstByte = data[0]!;

  // TLS ClientHello (HTTPS) — 首字节 0x16
  if (firstByte === 0x16) return "https";

  // HTTP 文本协议 — 检查常见 HTTP 方法
  const head = data.slice(0, Math.min(data.length, 128)).toString("utf-8").toLowerCase();
  if (
    head.startsWith("get ") ||
    head.startsWith("post ") ||
    head.startsWith("put ") ||
    head.startsWith("delete ") ||
    head.startsWith("head ") ||
    head.startsWith("patch ") ||
    head.startsWith("options ")
  ) {
    // 检查是否包含 WebSocket 升级头
    if (head.includes("upgrade") && head.includes("websocket")) {
      return "websocket";
    }
    return "http";
  }

  // 其他协议
  return "tcp";
}

export class Mode1Handler {
  private socks5Server: Socks5Server | null = null;
  private socks5ServerInstance: net.Server | null = null;
  private socks5Sockets = new Set<net.Socket>();
  private config: AppConfig;
  private encryptKey: Buffer;

  constructor(config: AppConfig, encryptKey: Buffer) {
    this.config = config;
    this.encryptKey = encryptKey;
  }

  start() {
    this.socks5ServerInstance = this.startSocks5();
  }

  async stop() {
    log("Mode1 正在关闭服务...", "INFO");
    if (this.socks5ServerInstance) {
      await this.closeServerForce(this.socks5ServerInstance, this.socks5Sockets);
      this.socks5ServerInstance = null;
    }
    this.socks5Server = null;
    log("Mode1 服务已关闭", "INFO");
  }

  // ============================================================
  // SOCKS5 代理 — 唯一入口
  // ============================================================

  private startSocks5(): net.Server {
    const createTunnel = async (
      host: string, port: number,
      firstData: Buffer,
      onData: (data: Buffer) => void,
      onClose: () => void,
    ): Promise<Tunnel> => {
      const protocol = detectProtocol(firstData);
      log(`Mode1 [${protocol}] ${host}:${port} (${firstData.length} bytes)`);

      // 所有协议统一通过 WebSocket 加密隧道
      return this.openTunnel(host, port, firstData, onData, onClose);
    };

    this.socks5Server = new Socks5Server(createTunnel);
    const server = this.socks5Server.start(this.config.socks5Port, this.config.bindHost);
    server.on("connection", (socket) => {
      this.socks5Sockets.add(socket);
      socket.on("close", () => this.socks5Sockets.delete(socket));
    });
    return server;
  }

  // ============================================================
  // WebSocket 加密隧道 — 统一通道
  // ============================================================

  private openTunnel(
    host: string, port: number,
    firstData: Buffer,
    onData: (data: Buffer) => void,
    onClose: () => void,
  ): Promise<Tunnel> {
    return new Promise((resolve, reject) => {
      const wsProto = resolveWsProtocol(this.config);
      const url = wsProto + '://' + this.config.remoteHost + ':' + this.config.remotePort + '/tunnel';
      const ws = new WebSocket(url);
      let settled = false;

      ws.onopen = () => {
        // 发送加密的隧道建立请求
        const tunnelReq = serializeTunnelRequest(host, port);
        const encryptedTunnelReq = pack(tunnelReq, this.encryptKey);
        ws.send(encryptedTunnelReq);
      };

      ws.onmessage = (event) => {
        const data = Buffer.isBuffer(event.data) ? event.data : Buffer.from(event.data as ArrayBuffer);

        if (!settled) {
          // 等待隧道建立成功响应
          const result = tryUnpack(data, this.encryptKey);
          if (result) {
            let cmd;
            try { cmd = parseCommand(result.data); } catch (e) {
              settled = true; reject(e); ws.close(); return;
            }
            if (cmd.type !== 'tunnel_ok') {
              settled = true; reject(new Error("tunnel failed")); ws.close(); return;
            }

            settled = true;

            const tunnel: Tunnel = {
              write: (d: Buffer) => {
                try { ws.send(packTunnelData(d, this.encryptKey)); } catch {}
              },
              close: () => {
                try { ws.close(); } catch {}
              },
            };

            // 隧道建立成功后，立即发送浏览器第一批数据
            if (firstData.length > 0) {
              tunnel.write(firstData);
            }

            resolve(tunnel);
          }
        } else {
          // 隧道数据（目标 → 浏览器）
          const r = tryUnpackTunnelData(data, this.encryptKey);
          if (r) { try { onData(r.data); } catch {} }
        }
      };

      ws.onerror = (err) => {
        log("Mode2 WS tunnel error: " + err.message, "ERROR");
        if (!settled) { settled = true; reject(err); }
        onClose();
      };

      ws.onclose = () => {
        onClose();
      };

      // 超时
      setTimeout(() => {
        if (!settled) { settled = true; reject(new Error("tunnel timeout")); ws.close(); }
      }, 15000);
    });
  }

  // ============================================================
  // 工具
  // ============================================================

  private closeServerForce(server: net.Server, sockets?: Set<net.Socket>): Promise<void> {
    return new Promise<void>((resolve) => {
      if (sockets) {
        for (const sock of sockets) {
          try { sock.destroy(); } catch {}
        }
        sockets.clear();
      }
      server.close(() => { resolve(); });
      server.unref();
      setTimeout(() => resolve(), 3000);
    });
  }

}