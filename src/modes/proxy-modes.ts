/**
 * 统一代理模式服务器
 *
 * 根据配置运行 Mode1 或 Mode2：
 *   Mode1 (加密端): 本地 HTTP/SOCKS5 代理，加密转发到 Mode2
 *   Mode2 (解密端): 远程解密转发服务器，解密后转发到真实目标
 *
 * 所有 wire 数据均为全加密，零明文元数据暴露。
 */
import net from "net";
import { ProxyServer } from "../core/proxy.js";
import { Socks5Server, type Tunnel } from "../core/socks5.js";
import { log } from "../utils.js";
import { type AppConfig } from "../config.js";
import {
  deriveKey,
  pack,
  tryUnpack,
  packTunnelData,
  tryUnpackTunnelData,
  serializeHttpRequest,
  serializeTunnelRequest,
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

/** Mode1 的 HTTP 客户端 socket 状态 */
interface HttpSocketState {
  buffer: Buffer;
  tunnel: Tunnel | null;
  clientIp: string;
}

export class ProxyModeServer {
  private config: AppConfig;
  private mode: "mode1" | "mode2";
  private encryptKey: Buffer;
  private proxy: ProxyServer;

  // Mode1 组件
  private httpServer: net.Server | null = null;
  private httpSockets = new Set<net.Socket>();
  private socks5Server: Socks5Server | null = null;
  private socks5ServerInstance: net.Server | null = null;
  private socks5Sockets = new Set<net.Socket>();

  // Mode1 → Mode2 HTTP 命令通道
  private mode2Conn: net.Socket | null = null;
  private mode2Buffer = Buffer.alloc(0);
  private pendingResolve: ((value: Buffer) => void) | null = null;
  private pendingReject: ((err: Error) => void) | null = null;

  // Mode2 组件
  private mode2ListenServer: net.Server | null = null;
  private mode2Connections = new Set<net.Socket>();

  constructor(config: AppConfig) {
    this.config = config;
    this.mode = config.proxyMode as "mode1" | "mode2";
    this.encryptKey = deriveKey(config.encryptPassword, config.encryptSalt);
    this.proxy = new ProxyServer();
  }

  start() {
    if (this.mode === "mode1") this.startMode1();
    else this.startMode2();
  }

  async stop() {
    if (this.mode === "mode1") await this.stopMode1();
    else await this.stopMode2();
  }

// ============================================================
  // Mode1 实现
  // ============================================================

  private startMode1() {
    this.createHttpServer();
    this.socks5ServerInstance = this.startSocks5();
    this.printMode1StartupInfo();
  }

  private async stopMode1() {
    log("Mode1 正在关闭服务...", "INFO");
    // 关闭 HTTP 代理服务器（强制断开所有连接）
    if (this.httpServer) {
      await this.closeServerForce(this.httpServer, this.httpSockets);
      this.httpServer = null;
    }
    // 关闭 SOCKS5 代理服务器
    if (this.socks5ServerInstance) {
      await this.closeServerForce(this.socks5ServerInstance, this.socks5Sockets);
      this.socks5ServerInstance = null;
    }
    this.socks5Server = null;
    // 关闭与 Mode2 的加密连接
    if (this.mode2Conn) {
      try { this.mode2Conn.destroy(); } catch {}
      this.mode2Conn = null;
    }
    log("Mode1 服务已关闭", "INFO");
  }

  private createHttpServer() {
    const server = net.createServer((socket) => {
      this.httpSockets.add(socket);
      socket.on("close", () => this.httpSockets.delete(socket));
      const state: HttpSocketState = {
        buffer: Buffer.alloc(0), tunnel: null,
        clientIp: socket.remoteAddress || "unknown",
      };
      socket.on("data", (d: Buffer) => {
        state.buffer = Buffer.concat([state.buffer, d]);
        this.processHttpBuffer(socket, state);
      });
      socket.on("close", () => this.cleanupHttpSocket(socket, state));
      socket.on("error", (e) => {
        log("HTTP 错误: " + e.message, "ERROR");
        this.cleanupHttpSocket(socket, state);
      });
    });
    server.listen(this.config.httpPort, this.config.bindHost, () => {
      log("HTTP 代理已启动: " + this.config.bindHost + ":" + this.config.httpPort);
    });
    this.httpServer = server;
  }

  private processHttpBuffer(socket: net.Socket, state: HttpSocketState) {
    // 隧道已建立：所有后续数据直接转发到加密隧道
    if (state.tunnel) {
      state.tunnel.write(state.buffer);
      state.buffer = Buffer.alloc(0);
      return;
    }
    const buf = state.buffer;
    const headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd === -1) {
      if (buf.length > 65536) this.cleanupHttpSocket(socket, state);
      return;
    }
    const headerPart = buf.slice(0, headerEnd).toString("utf-8");
    const bodyStr = buf.length > headerEnd + 4 ? buf.slice(headerEnd + 4).toString("utf-8") : "";
    const lines = headerPart.split("\r\n");
    const [method, path] = (lines[0] || "").split(" ");
    if (!method || !path) { this.cleanupHttpSocket(socket, state); return; }

    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const idx = lines[i]!.indexOf(":");
      if (idx > 0) headers[lines[i]!.slice(0, idx).trim()] = lines[i]!.slice(idx + 1).trim();
    }

    // CONNECT 隧道
    if (method.toUpperCase() === "CONNECT") {
      const [host, portStr] = path.split(":");
      const port = parseInt(portStr || "443", 10);
      this.handleConnect(socket, state, host!, port);
      state.buffer = Buffer.alloc(0);
      return;
    }

    // HTTP 请求转发
    const body = bodyStr ? Buffer.from(bodyStr, "utf-8") : undefined;
    this.handleHttpRequest(socket, state, method, path, headers, body);
    state.buffer = Buffer.alloc(0);
  }

  private async handleHttpRequest(
    socket: net.Socket, state: HttpSocketState,
    method: string, url: string, headers: Record<string, string>, body?: Buffer,
  ) {
    try {
      const data = await this.sendEncryptedCommand(serializeHttpRequest(method, url, headers, body));
      const cmd = parseCommand(data);
      if (cmd.type === "resp") {
        await this.sendHttpResponse(socket, cmd.statusCode, cmd.headers, cmd.body);
      }
    } catch (err) {
      log("Mode1 HTTP 错误: " + err, "ERROR");
      try { socket.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"); } catch {}
      this.cleanupHttpSocket(socket, state);
    }
  }

  private async handleConnect(socket: net.Socket, state: HttpSocketState, host: string, port: number) {
    try {
      const tunnel = await this.openTunnel(
        host, port,
        (data: Buffer) => { try { socket.write(data); } catch {} },
        () => { try { socket.end(); } catch {} },
      );
      state.tunnel = tunnel;

      log("CONNECT 隧道建立成功: " + host + ":" + port);
      try { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); } catch {}

      // 后续数据流由 processHttpBuffer 的隧道分支处理（state.tunnel 非空时直接转发）
    } catch (err) {
      log("CONNECT 隧道建立失败 " + host + ":" + port + " - " + err, "ERROR");
      try { socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch {}
      this.cleanupHttpSocket(socket, state);
    }
  }

  /**
   * 建立一条专用加密隧道连接到 Mode2。
   * 每个隧道使用独立 TCP 连接，避免与 HTTP 命令通道的数据流混淆。
   */
  private openTunnel(
    host: string, port: number,
    onData: (data: Buffer) => void,
    onClose: () => void,
  ): Promise<Tunnel> {
    return new Promise((resolve, reject) => {
      const conn = net.createConnection(
        { host: this.config.remoteHost, port: this.config.remotePort },
        () => {
          const tunnelReq = serializeTunnelRequest(host, port);
          const encryptedTunnelReq = pack(tunnelReq, this.encryptKey);          conn.write(encryptedTunnelReq);
        },
      );

      let settled = false;
      conn.on("error", (err) => {
        log("Mode2 隧道连接错误: " + err.message, "ERROR");
        if (!settled) { settled = true; reject(err); }
        onClose();
      });
      conn.on("close", () => { onClose(); });

      // 等待 TUNNEL_OK
      let handshakeBuf = Buffer.alloc(0);
      const onHandshake = (data: Buffer) => {
        handshakeBuf = Buffer.concat([handshakeBuf, data]);
        const result = tryUnpack(handshakeBuf, this.encryptKey);
        if (!result) return;
        conn.removeListener("data", onHandshake);
        handshakeBuf = handshakeBuf.subarray(result.consumed);

        let cmd: ParsedCommand;
        try {
          cmd = parseCommand(result.data);
        } catch (err) {
          if (!settled) { settled = true; reject(err as Error); }
          conn.destroy();
          return;
        }
        if (!settled && cmd.type !== "tunnel_ok") {
          settled = true;
          conn.destroy();
          reject(new Error("隧道建立失败"));
          return;
        }

        // 隧道已建立：切换为隧道数据流解析
        let tunnelBuffer = handshakeBuf;
        const onTunnelData = (chunk: Buffer) => {
          tunnelBuffer = Buffer.concat([tunnelBuffer, chunk]);
          while (true) {
            const r = tryUnpackTunnelData(tunnelBuffer, this.encryptKey);
            if (!r) break;
            tunnelBuffer = tunnelBuffer.subarray(r.consumed);
            try { onData(r.data); } catch {}
          }
        };
        conn.on("data", onTunnelData);

        const tunnel: Tunnel = {
          write: (d: Buffer) => {
            if (!conn.destroyed) {
              try {
                const tunnelEncrypted = packTunnelData(d, this.encryptKey);                conn.write(tunnelEncrypted);
              } catch {}
            }
          },
          close: () => {
            conn.removeListener("data", onTunnelData);
            if (!conn.destroyed) {
              try {
                const closePayload = serializeClose();
                const closeEncrypted = pack(closePayload, this.encryptKey);                conn.write(closeEncrypted);
              } catch {}
            }
            try { conn.destroy(); } catch {}
          },
        };

        // 处理 TUNNEL_OK 后紧随的隧道数据
        if (tunnelBuffer.length > 0) {
          const tmp = tunnelBuffer;
          tunnelBuffer = Buffer.alloc(0);
          onTunnelData(tmp);
        }

        if (!settled) { settled = true; resolve(tunnel); }
      };
      conn.on("data", onHandshake);

      setTimeout(() => {
        conn.removeListener("data", onHandshake);
        if (!settled) { settled = true; reject(new Error("隧道响应超时")); }
        if (!conn.destroyed) conn.destroy();
      }, 15000);
    });
  }

  private async sendHttpResponse(
    socket: net.Socket, statusCode: number,
    headers: Record<string, string> | undefined, body?: Buffer,
  ) {
    const statusText = statusCode === 200 ? "OK" : statusCode === 302 ? "Found"
      : statusCode === 404 ? "Not Found" : statusCode === 500 ? "Internal Server Error"
      : statusCode === 502 ? "Bad Gateway" : statusCode === 403 ? "Forbidden"
      : statusCode === 301 ? "Moved Permanently" : statusCode === 304 ? "Not Modified" : "";
    const sl = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n";
    const hl: string[] = [];
    if (headers) { for (const [k, v] of Object.entries(headers)) hl.push(k + ": " + v); }
    if (!headers || (!headers["Connection"] && !headers["connection"])) hl.push("Connection: close");
    try { socket.write(sl + hl.join("\r\n") + "\r\n\r\n"); } catch {}
    if (body) { try { socket.write(body); } catch {} }
    try { socket.end(); } catch {}
  }

  private getMode2Connection(): Promise<net.Socket> {
    if (this.mode2Conn && !this.mode2Conn.destroyed) return Promise.resolve(this.mode2Conn);
    return new Promise((resolve, reject) => {
      const conn = net.createConnection(
        { host: this.config.remoteHost, port: this.config.remotePort },
        () => { this.mode2Conn = conn; this.setupMode2Read(conn); resolve(conn); },
      );
      conn.on("error", (err) => {
        log("Mode2 连接失败: " + err.message, "ERROR");
        this.mode2Conn = null;
        reject(err);
      });
    });
  }

  private setupMode2Read(conn: net.Socket) {
    conn.on("data", (data: Buffer) => {
      this.mode2Buffer = Buffer.concat([this.mode2Buffer, data]);
      while (true) {
        const result = tryUnpack(this.mode2Buffer, this.encryptKey);
        if (!result) break;
        this.mode2Buffer = this.mode2Buffer.subarray(result.consumed);
        if (this.pendingResolve) {
          const r = this.pendingResolve;
          this.pendingResolve = null;
          this.pendingReject = null;
          r(result.data);
        }
      }
    });
  }

  private sendEncryptedCommand(payload: Buffer): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        const conn = await this.getMode2Connection();
        this.pendingResolve = resolve;
        this.pendingReject = reject;
        const encrypted = pack(payload, this.encryptKey);        conn.write(encrypted);
        setTimeout(() => {
          if (this.pendingResolve) {
            this.pendingResolve = null;
            this.pendingReject = null;
            reject(new Error("Mode2 响应超时"));
          }
        }, 30000);
      } catch (err) { reject(err); }
    });
  }

  private startSocks5(): net.Server {
    const createTunnel = async (
      host: string, port: number,
      onData: (data: Buffer) => void, onClose: () => void,
    ): Promise<Tunnel> => {
      return this.openTunnel(host, port, onData, onClose);
    };

    this.socks5Server = new Socks5Server(createTunnel);
    const server = this.socks5Server.start(this.config.socks5Port, this.config.bindHost);
    // 跟踪 SOCKS5 的 socket 连接，以便关闭时强制销毁
    server.on("connection", (socket) => {
      this.socks5Sockets.add(socket);
      socket.on("close", () => this.socks5Sockets.delete(socket));
    });
    return server;
  }

  private cleanupHttpSocket(socket: net.Socket, state: HttpSocketState) {
    if (state.tunnel) {
      try { state.tunnel.close(); } catch {}
      state.tunnel = null;
    }
    try { socket.end(); } catch {}
  }

  private printMode1StartupInfo() {
    log("============================================");
    log("Mode1 加密代理已启动");
    log("  HTTP 代理:     http://" + this.config.bindHost + ":" + this.config.httpPort);
    log("  HTTPS CONNECT: 支持（加密隧道）");
    log("  SOCKS5 代理:   socks5://" + this.config.bindHost + ":" + this.config.socks5Port);
    log("  加密隧道:      -> " + this.config.remoteHost + ":" + this.config.remotePort);
    log("============================================");
  }

  // ============================================================
  // Mode2 实现
  // ============================================================

  private startMode2() {
    const server = net.createServer((conn) => {
      log("Mode2 收到加密连接: " + conn.remoteAddress);
      this.mode2Connections.add(conn);

      const state: Mode2ConnState = {
        buffer: Buffer.alloc(0), mode: "idle",
        targetSocket: null, targetHost: "", targetPort: 0,
      };

      conn.on("data", (data: Buffer) => {
        state.buffer = Buffer.concat([state.buffer, data]);
        this.processMode2Buffer(conn, state);
      });
      conn.on("close", () => {
        this.mode2Connections.delete(conn);
        this.cleanupMode2State(state);
        log("Mode2 加密连接关闭");
      });
      conn.on("error", (err) => {
        log("Mode2 连接错误: " + err.message, "ERROR");
        this.cleanupMode2State(state);
      });
    });

    server.listen(this.config.encryptListenPort, this.config.encryptListenHost, () => {
      log("Mode2 解密转发服务器已启动: " + this.config.encryptListenHost + ":" + this.config.encryptListenPort);
    });
    this.mode2ListenServer = server;
  }

  private async stopMode2() {
    log("Mode2 正在关闭服务...", "INFO");
    // 先关闭所有加密连接
    for (const conn of this.mode2Connections) {
      try { conn.destroy(); } catch {}
    }
    this.mode2Connections.clear();
    // 关闭监听服务器
    if (this.mode2ListenServer) {
      await this.closeServerForce(this.mode2ListenServer);
      this.mode2ListenServer = null;
    }
    log("Mode2 服务已关闭", "INFO");
  }

  private processMode2Buffer(conn: net.Socket, state: Mode2ConnState) {
    // 隧道模式：处理加密隧道数据流
    if (state.mode === "tunnel") {
      while (true) {
        const result = tryUnpackTunnelData(state.buffer, this.encryptKey);
        if (!result) break;
        state.buffer = state.buffer.subarray(result.consumed);
        if (state.targetSocket) { try { state.targetSocket.write(result.data); } catch {} }
      }
      return;
    }

    // 命令模式：处理加密命令帧
    while (true) {
      const result = tryUnpack(state.buffer, this.encryptKey);
      if (!result) break;
      state.buffer = state.buffer.subarray(result.consumed);
      try {
        const cmd = parseCommand(result.data);
        this.handleMode2Command(conn, state, cmd);
      } catch (err) {
        log("Mode2 命令处理错误: " + err, "ERROR");
      }
    }
  }

  private async handleMode2Command(
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
            this.cleanupMode2State(state);
          });
          target.on("error", (err) => {
            log("目标连接错误 " + host + ":" + port + " - " + err.message, "ERROR");
            this.cleanupMode2State(state);
          });
        } catch (err) {
          log("Mode2 隧道连接失败 " + host + ":" + port + ": " + err, "ERROR");
          const errorResp = serializeHttpResponse(502, {});
          try { conn.write(pack(errorResp, this.encryptKey)); } catch {}
          this.cleanupMode2State(state);
        }
        break;
      }

      case "close": {
        log("Mode2 收到关闭命令");
        this.cleanupMode2State(state);
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

  private cleanupMode2State(state: Mode2ConnState) {
    if (state.targetSocket) {
      try { state.targetSocket.end(); } catch {}
      state.targetSocket = null;
    }
    state.mode = "idle";
  }

  /**
   * 强制关闭 TCP 服务器：先停止接受新连接，再销毁所有现有连接，确保端口立即释放。
   * @param sockets 可选的 socket 集合，如果不传则尝试通过 server 的 connection 事件获取
   */
  private closeServerForce(server: net.Server, sockets?: Set<net.Socket>): Promise<void> {
    return new Promise<void>((resolve) => {
      // 如果传入了 socket 集合，强制销毁所有连接
      if (sockets) {
        for (const sock of sockets) {
          try { sock.destroy(); } catch {}
        }
        sockets.clear();
      }
      // 关闭服务器（停止接受新连接，等待所有连接关闭后回调）
      server.close(() => {
        resolve();
      });
      // 解除引用，允许进程退出
      server.unref();
      // 超时保护：如果 3 秒后还没回调，强制 resolve
      setTimeout(() => resolve(), 3000);
    });
  }
}