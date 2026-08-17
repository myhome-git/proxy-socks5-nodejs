/**
 * Mode1 加密端实现
 *
 * 本地 HTTP/SOCKS5 代理，通过加密隧道转发到 Mode2
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
  parseCommand,
} from "../security/sbox.js";

/** Mode1 HTTP 客户端 socket 状态 */
interface HttpSocketState {
  buffer: Buffer;
  tunnel: Tunnel | null;
  clientIp: string;
}

export class Mode1Handler {
  private httpServer: net.Server | null = null;
  private httpSockets = new Set<net.Socket>();
  private socks5Server: Socks5Server | null = null;
  private socks5ServerInstance: net.Server | null = null;
  private socks5Sockets = new Set<net.Socket>();
  private config: AppConfig;
  private encryptKey: Buffer;
  private proxy: ProxyServer;

  constructor(config: AppConfig, encryptKey: Buffer, proxy: ProxyServer) {
    this.config = config;
    this.encryptKey = encryptKey;
    this.proxy = proxy;
  }

  start() {
    this.createHttpServer();
    this.socks5ServerInstance = this.startSocks5();
    this.printStartupInfo();
  }

  async stop() {
    log("Mode1 正在关闭服务...", "INFO");
    if (this.httpServer) {
      await this.closeServerForce(this.httpServer, this.httpSockets);
      this.httpServer = null;
    }
    if (this.socks5ServerInstance) {
      await this.closeServerForce(this.socks5ServerInstance, this.socks5Sockets);
      this.socks5ServerInstance = null;
    }
    this.socks5Server = null;
    log("Mode1 服务已关闭", "INFO");
  }

  // ============================================================
  // HTTP 代理
  // ============================================================

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
      log("HTTP 代理已启动 " + this.config.bindHost + ":" + this.config.httpPort);
    });
    this.httpServer = server;
  }

  private processHttpBuffer(socket: net.Socket, state: HttpSocketState) {
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

    if (method.toUpperCase() === "CONNECT") {
      const [host, portStr] = path.split(":");
      const port = parseInt(portStr || "443", 10);
      this.handleConnect(socket, state, host!, port);
      state.buffer = Buffer.alloc(0);
      return;
    }

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
    } catch (err) {
      log("CONNECT 隧道建立失败 " + host + ":" + port + " - " + err, "ERROR");
      try { socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch {}
      this.cleanupHttpSocket(socket, state);
    }
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

  private cleanupHttpSocket(socket: net.Socket, state: HttpSocketState) {
    if (state.tunnel) {
      try { state.tunnel.close(); } catch {}
      state.tunnel = null;
    }
    try { socket.end(); } catch {}
  }
// ============================================================
  // 加密隧道
  // ============================================================

  private openTunnel(
    host: string, port: number,
    onData: (data: Buffer) => void,
    onClose: () => void,
  ): Promise<Tunnel> {
    return new Promise((resolve, reject) => {
      const wsProto = this.config.remoteProtocol === 'https' ? 'wss' : 'ws';
      const url = wsProto + '://' + this.config.remoteHost + ':' + this.config.remotePort + '/tunnel';
      const ws = new globalThis.WebSocket(url);
      let settled = false;
      ws.onopen = () => {
        const tunnelReq = serializeTunnelRequest(host, port);
        const encryptedTunnelReq = pack(tunnelReq, this.encryptKey);
        ws.send(encryptedTunnelReq);
      };
      ws.onmessage = (event) => {
        const data = Buffer.from(event.data);
        if (!settled) {
          const result = tryUnpack(data, this.encryptKey);
          if (result) {
            let cmd;
            try { cmd = parseCommand(result.data); } catch (e) { settled = true; reject(e); ws.close(); return; }
            if (cmd.type !== 'tunnel_ok') { settled = true; reject(new Error("tunnel failed")); ws.close(); return; }
            settled = true;
            const tunnel = {
              write: (d: Buffer) => { try { ws.send(packTunnelData(d, this.encryptKey)); } catch {} },
              close: () => { try { ws.close(); } catch {} },
            };
            resolve(tunnel);
          }
        } else {
          const r = tryUnpackTunnelData(data, this.encryptKey);
          if (r) { try { onData(r.data); } catch {} }
        }
      };
      ws.onerror = (err) => {
        log("Mode2 WS tunnel error: " + err.message, "ERROR");
        if (!settled) { settled = true; reject(err); }
        onClose();
      };
      ws.onclose = () => { onClose(); };
      setTimeout(() => {
        if (!settled) { settled = true; reject(new Error("tunnel timeout")); ws.close(); }
      }, 15000);
    });
  }

  private async sendEncryptedCommand(payload: Buffer): Promise<Buffer> {
    const url = this.config.remoteProtocol + '://' + this.config.remoteHost + ':' + this.config.remotePort + '/command';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        body: payload,
        headers: { 'Content-Type': 'application/octet-stream' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const buf = Buffer.from(await resp.arrayBuffer());
      const result = tryUnpack(buf, this.encryptKey);
      if (!result) throw new Error('decrypt failed');
      return result.data;
    } catch (err) {
      clearTimeout(timeout);
      throw err;
    }
  }

  // ============================================================
  // SOCKS5 代理
  // ============================================================

  private startSocks5(): net.Server {
    const createTunnel = async (
      host: string, port: number,
      onData: (data: Buffer) => void, onClose: () => void,
    ): Promise<Tunnel> => {
      return this.openTunnel(host, port, onData, onClose);
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

  private printStartupInfo() {
    log("============================================");
    log("Mode1 加密代理已启动");
    log("  HTTP 代理:     http://" + this.config.bindHost + ":" + this.config.httpPort);
    log("  HTTPS CONNECT: 支持（加密隧道）");
    log("  SOCKS5 代理:   socks5://" + this.config.bindHost + ":" + this.config.socks5Port);
    log("  加密隧道:      " + this.config.remoteProtocol + "://" + this.config.remoteHost + ":" + this.config.remotePort);
    log("============================================");
  }
}