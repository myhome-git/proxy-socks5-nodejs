/**
 * Mode2 解密端实现
 *
 * 远程解密转发服务器，收到加密数据后解密，转发到真实目标
 */
import net from "net";
import { ProxyServer } from "../core/proxy.js";
import { log } from "../utils.js";
import { type AppConfig } from "../config.js";
import {
  pack,
  tryUnpack,
  packTunnelData,
  tryUnpackTunnelData,
  serializeHttpResponse,
  serializeTunnelOk,
  serializeClose,
  parseCommand,
  type ParsedCommand,
} from "../security/sbox.js";

/** Mode2 连接状态 */
interface Mode2ConnState {
  buffer: Buffer;
  mode: "idle" | "tunnel";
  targetSocket: net.Socket | null;
  targetHost: string;
  targetPort: number;
}

export class Mode2Handler {
  private listenServer: net.Server | null = null;
  private connections = new Set<net.Socket>();
  private config: AppConfig;
  private encryptKey: Buffer;
  private proxy: ProxyServer;

  constructor(config: AppConfig, encryptKey: Buffer, proxy: ProxyServer) {
    this.config = config;
    this.encryptKey = encryptKey;
    this.proxy = proxy;
  }

  start() {
    const server = net.createServer((conn) => {
      log("Mode2 收到加密连接: " + conn.remoteAddress);
      this.connections.add(conn);

      const state: Mode2ConnState = {
        buffer: Buffer.alloc(0), mode: "idle",
        targetSocket: null, targetHost: "", targetPort: 0,
      };

      conn.on("data", (data: Buffer) => {
        state.buffer = Buffer.concat([state.buffer, data]);
        this.processBuffer(conn, state);
      });
      conn.on("close", () => {
        this.connections.delete(conn);
        this.cleanupState(state);
        log("Mode2 加密连接关闭");
      });
      conn.on("error", (err) => {
        log("Mode2 连接错误: " + err.message, "ERROR");
        this.cleanupState(state);
      });
    });

    server.listen(this.config.encryptListenPort, this.config.encryptListenHost, () => {
      log("Mode2 解密转发服务器已启动: " + this.config.encryptListenHost + ":" + this.config.encryptListenPort);
    });
    this.listenServer = server;
  }

  async stop() {
    log("Mode2 正在关闭服务...", "INFO");
    for (const conn of this.connections) {
      try { conn.destroy(); } catch {}
    }
    this.connections.clear();
    if (this.listenServer) {
      await this.closeServerForce(this.listenServer);
      this.listenServer = null;
    }
    log("Mode2 服务已关闭", "INFO");
  }

  private processBuffer(conn: net.Socket, state: Mode2ConnState) {
    if (state.mode === "tunnel") {
      while (true) {
        const result = tryUnpackTunnelData(state.buffer, this.encryptKey);
        if (!result) break;
        state.buffer = state.buffer.subarray(result.consumed);
        if (state.targetSocket) { try { state.targetSocket.write(result.data); } catch {} }
      }
      return;
    }

    while (true) {
      const result = tryUnpack(state.buffer, this.encryptKey);
      if (!result) break;
      state.buffer = state.buffer.subarray(result.consumed);
      try {
        const cmd = parseCommand(result.data);
        this.handleCommand(conn, state, cmd);
      } catch (err) {
        log("Mode2 命令处理错误: " + err, "ERROR");
      }
    }
  }

  private async handleCommand(
    conn: net.Socket, state: Mode2ConnState, cmd: ParsedCommand,
  ) {
    switch (cmd.type) {
      case "http": {
        log("Mode2 HTTP 转发: " + cmd.method + " " + cmd.url);
        try {
          const cleanedHeaders = this.cleanForwardHeaders(cmd.headers);
          const request = new Request(cmd.url, {
            method: cmd.method,
            headers: cleanedHeaders,
            body: cmd.body,
          });
          const response = await this.proxy.handleRequest(request, true);
          const respHeaders: Record<string, string> = {};
          response.headers.forEach((value, key) => {
            const lk = key.toLowerCase();
            if (!["transfer-encoding", "keep-alive", "connection"].includes(lk)) {
              respHeaders[key] = value;
            }
          });
          let body: Buffer | undefined;
          if (response.body) body = Buffer.from(await response.arrayBuffer());
          conn.write(pack(serializeHttpResponse(response.status, respHeaders, body), this.encryptKey));
          log("Mode2 HTTP 响应: " + response.status + " " + cmd.url);
        } catch (err) {
          log("Mode2 HTTP 转发失败: " + err, "ERROR");
          const errorResp = serializeHttpResponse(502, {}, Buffer.from("Proxy Error: " + err));
          try { conn.write(pack(errorResp, this.encryptKey)); } catch {}
        }
        break;
      }

      case "tunnel": {
        const host = cmd.host;
        const port = cmd.port;
        log("Mode2 隧道建立: " + host + ":" + port);
        state.mode = "idle";
        state.targetHost = host;
        state.targetPort = port;
        try {
          const target = await new Promise<net.Socket>((resolve, reject) => {
            const socket = net.createConnection({ host, port }, () => resolve(socket));
            socket.on("error", (err) => reject(err));
          });
          state.targetSocket = target;
          state.mode = "tunnel";
          conn.write(pack(serializeTunnelOk(), this.encryptKey));
          log("Mode2 隧道建立成功: " + host + ":" + port);

          target.on("data", (targetData: Buffer) => {
            try { conn.write(packTunnelData(targetData, this.encryptKey)); } catch {}
          });
          target.on("close", () => {
            try { conn.write(pack(serializeClose(), this.encryptKey)); } catch {}
            this.cleanupState(state);
          });
          target.on("error", (err) => {
            log("目标连接错误 " + host + ":" + port + " - " + err.message, "ERROR");
            this.cleanupState(state);
          });
        } catch (err) {
          log("Mode2 隧道连接失败 " + host + ":" + port + ": " + err, "ERROR");
          const errorResp = serializeHttpResponse(502, {});
          try { conn.write(pack(errorResp, this.encryptKey)); } catch {}
          this.cleanupState(state);
        }
        break;
      }

      case "close": {
        log("Mode2 收到关闭命令");
        this.cleanupState(state);
        break;
      }

      default:
        log("Mode2 未知命令类型", "WARN");
    }
  }

  private cleanForwardHeaders(headers: Record<string, string>): Record<string, string> {
    const leakHeaders = new Set([
      "x-forwarded-for", "x-real-ip", "x-client-ip", "client-ip",
      "forwarded", "via", "x-proxy-user-ip", "cf-connecting-ip",
      "true-client-ip", "x-originating-ip", "x-forwarded-host",
      "x-forwarded-proto", "x-forwarded-port", "x-forwarded-server",
      "x-cluster-client-ip", "x-remote-ip", "x-remote-addr",
      "forwarded-for", "x-request-id",
      "proxy-connection", "proxy-authorization", "proxy-authenticate",
      "x-cache", "x-cache-hit", "x-akamai-transformed",
    ]);
    const cleaned: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (!leakHeaders.has(key.toLowerCase())) cleaned[key] = value;
    }
    return cleaned;
  }

  private cleanupState(state: Mode2ConnState) {
    if (state.targetSocket) {
      try { state.targetSocket.end(); } catch {}
      state.targetSocket = null;
    }
    state.mode = "idle";
  }

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