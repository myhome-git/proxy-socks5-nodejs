/**
 * Mode2 解密端实现
 *
 * 仅 WebSocket /tunnel 服务器，接收 Mode1 的加密隧道请求。
 * 收到隧道建立请求后，连接目标并双向加密转发。
 */
import http from "http";
import net from "net";
import { WebSocketServer, WebSocket } from "ws";
import { log } from "../utils.js";
import { type AppConfig } from "../config.js";
import {
  pack, tryUnpack,
  packTunnelData, tryUnpackTunnelData,
  serializeTunnelOk, serializeClose,
  parseCommand,
} from "../security/sbox.js";

/**
 * 生成数据前 N 字节的十六进制预览字符串
 */
function hexPreview(data: Buffer, maxBytes: number = 32): string {
  const len = Math.min(data.length, maxBytes);
  const hex = data.subarray(0, len).toString("hex").toUpperCase();
  return hex;
}

export class Mode2Handler {
  private httpServer: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private config: AppConfig;
  private encryptKey: Buffer;

  constructor(config: AppConfig, encryptKey: Buffer) {
    this.config = config;
    this.encryptKey = encryptKey;
  }

  start() {
    const server = http.createServer();

    // WebSocket 服务器 (路径 /tunnel)
    const wss = new WebSocketServer({ server, path: "/tunnel" });
    wss.on("connection", (ws) => {
      this.handleWebSocket(ws);
    });

    server.listen(this.config.encryptListenPort, this.config.encryptListenHost, () => {
      log(`Mode2 服务器已启动: ${this.config.encryptListenHost}:${this.config.encryptListenPort}`);
      log(`  WebSocket 隧道: /tunnel`);
    });

    this.httpServer = server;
    this.wss = wss;
  }

  async stop() {
    log("Mode2 正在关闭服务...", "INFO");
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => resolve());
        this.httpServer!.unref();
      });
      this.httpServer = null;
    }
    log("Mode2 服务已关闭", "INFO");
  }

  // ============================================================
  // WebSocket /tunnel — 处理所有隧道流量
  // ============================================================

  private handleWebSocket(ws: WebSocket) {
    log("Mode2 WebSocket 隧道连接建立");

    let targetConn: net.Socket | null = null;

      // 等待第一条加密消息 (隧道建立请求)
      ws.once("message", (data) => {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
        const result = tryUnpack(buf, this.encryptKey);
        if (!result) {
          log("Mode2 WS 隧道解密失败", "ERROR");
          ws.close();
          return;
        }

        try {
          const cmd = parseCommand(result.data);
          if (cmd.type === "tunnel") {
            // 建立到目标的 TCP 连接
            this.connectTarget(ws, cmd.host, cmd.port);
          } else {
            log(`Mode2 WS 未知命令类型: ${cmd.type}`, "WARN");
            ws.close();
          }
        } catch (err) {
          log(`Mode2 WS 命令解析失败: ${err}`, "ERROR");
          ws.close();
        }
      });

    ws.on("error", () => {});
  }

  /**
   * 连接到目标服务器，并处理双向加密转发
   */
  private connectTarget(ws: WebSocket, host: string, port: number) {
    log(`Mode2 隧道建立: ${host}:${port}`);

    let closed = false;
    // 缓存建立连接前收到的隧道数据
    let pendingData: Buffer[] = [];
    let targetConn: net.Socket | null = null;

    const target = net.createConnection({ host, port }, () => {
      log(`Mode2 隧道建立成功: ${host}:${port}`);

      // 发送隧道建立成功响应
      try {
        ws.send(pack(serializeTunnelOk(), this.encryptKey));
      } catch {}

      // 发送缓存的隧道数据
      for (const d of pendingData) {
        try { target.write(d); } catch {}
      }
      pendingData = [];
    });

    // 目标 → 加密 → Mode1
    target.on("data", (targetData) => {
      if (closed) return;
      const encrypted = packTunnelData(targetData, this.encryptKey);
      if (this.config.debugLog) {
        log(`Mode2 收到响应内容 ${host}:${port} tcp 原始（bytes）: ${targetData.length}  加密（bytes）: ${encrypted.length}`);
      }
      try { ws.send(encrypted); } catch {}
    });

    target.on("close", () => {
      if (closed) return;
      closed = true;
      try {
        ws.send(pack(serializeClose(), this.encryptKey));
      } catch {}
      try { ws.close(); } catch {}
    });

    target.on("error", (err) => {
      if (closed) return;
      closed = true;
      log(`目标连接错误 ${host}:${port} - ${err.message}`, "ERROR");
      // 如果目标连接失败，通知 Mode1
      try {
        ws.send(pack(serializeClose(), this.encryptKey));
      } catch {}
      try { ws.close(); } catch {}
    });

    // Mode1 加密数据 → 解密 → 目标
    ws.on("message", (data) => {
      if (closed) return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
      const result = tryUnpackTunnelData(buf, this.encryptKey);
      if (result) {
        if (this.config.debugLog) {
          log(`Mode2 收到请求内容 ${host}:${port} tcp 原始（bytes）: ${buf.length}  解密（bytes）: ${result.data.length}`);
        }
        if (targetConn) {
          try { target.write(result.data); } catch {}
        } else {
          // 目标连接尚未建立，缓存数据
          pendingData.push(result.data);
        }
      }
    });

    ws.on("close", () => {
      if (closed) return;
      closed = true;
      log(`Mode2 隧道关闭: ${host}:${port}`);
      try { target.end(); } catch {}
    });

    ws.on("error", () => {
      if (closed) return;
      closed = true;
      try { target.end(); } catch {}
    });

    // 超时处理
    target.setTimeout(300000, () => {
      if (closed) return;
      closed = true;
      log(`Mode2 隧道超时: ${host}:${port}`, "WARN");
      try { target.end(); } catch {}
      try { ws.close(); } catch {}
    });

    targetConn = target;
  }
}