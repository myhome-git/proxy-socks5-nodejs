/**
 * SOCKS5 代理协议实现
 *
 * 支持 CONNECT 命令，建立 TCP 隧道转发。
 * 无认证模式。
 * 所有流量通过加密隧道（Tunnel）转发到 Mode2。
 */
import net from "net";
import { log } from "../utils.js";

// SOCKS5 协议常量
const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
const REP_SUCCESS = 0x00;
const REP_GENERAL_FAILURE = 0x01;
const REP_CMD_NOT_SUPPORTED = 0x07;
const REP_ATYP_NOT_SUPPORTED = 0x08;
const REP_HOST_UNREACHABLE = 0x04;

// 认证方法
const AUTH_NONE = 0x00;
const AUTH_USER_PASS = 0x02;
const AUTH_NO_ACCEPTABLE = 0xff;

/** 加密隧道接口 */
export interface Tunnel {
  write(data: Buffer): void;
  close(): void;
}

/** 隧道创建回调 */
export type TunnelCreator = (
  host: string,
  port: number,
  onData: (data: Buffer) => void,
  onClose: () => void,
) => Promise<Tunnel>;

export class Socks5Server {
  private createTunnel: TunnelCreator;

  constructor(
    createTunnel?: TunnelCreator,
  ) {
    this.createTunnel =
      createTunnel ||
      // 默认回退：直接 TCP 连接（不加密，仅用于无隧道场景）
      (async (host, port, onData, onClose) => {
        const socket = net.createConnection({ host, port }, () => {});
        socket.on("data", onData);
        socket.on("close", onClose);
        socket.on("error", (e) => {
          log(`目标连接错误 ${host}:${port} - ${e.message}`, "ERROR");
          onClose();
        });
        return {
          write: (d: Buffer) => { try { socket.write(d); } catch {} },
          close: () => { try { socket.end(); } catch {} },
        };
      });
  }

  start(port: number, hostname = "127.0.0.1"): net.Server {
    const server = net.createServer((ws) => {
      (ws as any)._state = "handshake";
      (ws as any)._buffer = Buffer.alloc(0);
      (ws as any)._targetHost = "";
      (ws as any)._targetPort = 0;
      (ws as any)._targetSocket = null;

      ws.on("data", (data) => {
        const state = (ws as any)._state;
        if (state === "handshake") this.handleHandshake(ws, data);
        else if (state === "request") this.handleRequest(ws, data);
        else if (state === "forward") {
          const tunnel = (ws as any)._tunnel as Tunnel | null;
          if (tunnel) tunnel.write(data);
        }
      });

      ws.on("close", () => {
        const tunnel = (ws as any)._tunnel as Tunnel | null;
        if (tunnel) { try { tunnel.close(); } catch {} }
      });

      ws.on("error", (error) => {
        log(`SOCKS5 错误: ${error.message}`, "ERROR");
        this.cleanup(ws);
      });
    });

    server.listen(port, hostname, () => {
      log(`SOCKS5 代理已启动: ${hostname}:${port}`);
    });
    return server;
  }

  private handleHandshake(ws: any, data: Buffer) {
    if (data.length < 3) { this.cleanup(ws); return; }
    const ver = data[0]!;
    const nmethods = data[1]!;
    if (ver !== SOCKS_VERSION || data.length < 2 + nmethods) {
      ws.write(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
      this.cleanup(ws);
      return;
    }

    // 无认证模式，直接选择 AUTH_NONE
    ws.write(Buffer.from([SOCKS_VERSION, AUTH_NONE]));
    (ws as any)._state = "request";
  }

  private async handleRequest(ws: any, data: Buffer) {
    if (data.length < 10) { this.sendReply(ws, REP_GENERAL_FAILURE); this.cleanup(ws); return; }
    const ver = data[0]!; const cmd = data[1]!; const atyp = data[3]!;
    if (ver !== SOCKS_VERSION || cmd !== CMD_CONNECT) {
      this.sendReply(ws, cmd !== CMD_CONNECT ? REP_CMD_NOT_SUPPORTED : REP_GENERAL_FAILURE);
      this.cleanup(ws); return;
    }

    let host = ""; let port = 0; let offset = 4;
    try {
      if (atyp === ATYP_IPV4) {
        if (data.length < offset + 6) throw new Error("数据不足");
        host = `${data[offset]}.${data[offset+1]}.${data[offset+2]}.${data[offset+3]}`;
        offset += 4;
      } else if (atyp === ATYP_DOMAIN) {
        const len = data[offset]!; offset += 1;
        if (data.length < offset + len + 2) throw new Error("数据不足");
        host = data.slice(offset, offset + len).toString("utf-8"); offset += len;
      } else if (atyp === ATYP_IPV6) {
        this.sendReply(ws, REP_ATYP_NOT_SUPPORTED); this.cleanup(ws); return;
      } else {
        this.sendReply(ws, REP_ATYP_NOT_SUPPORTED); this.cleanup(ws); return;
      }
      port = (data[offset]! << 8) | data[offset + 1]!;
    } catch (err) {
      log(`SOCKS5 解析地址失败: ${err}`, "ERROR");
      this.sendReply(ws, REP_GENERAL_FAILURE); this.cleanup(ws); return;
    }
    (ws as any)._targetHost = host; (ws as any)._targetPort = port;
    log(`SOCKS5 CONNECT: ${host}:${port}`);

    // 通过加密隧道建立目标连接
    try {
      const tunnel = await this.createTunnel(
        host,
        port,
        (data: Buffer) => { try { ws.write(data); } catch {} },
        () => { try { ws.end(); } catch {} },
      );

      this.sendReply(ws, REP_SUCCESS, host, port);
      (ws as any)._state = "forward";
      (ws as any)._tunnel = tunnel;
    } catch (err) {
      log(`连接目标失败 ${host}:${port} - ${err}`, "ERROR");
      this.sendReply(ws, REP_HOST_UNREACHABLE);
      this.cleanup(ws);
    }
  }

  private sendReply(ws: any, rep: number, host = "0.0.0.0", port = 0) {
    const buf = Buffer.alloc(10);
    buf[0] = SOCKS_VERSION; buf[1] = rep; buf[2] = 0x00; buf[3] = ATYP_IPV4;
    const parts = host.split(".");
    for (let i = 0; i < 4; i++) buf[4 + i] = parseInt(parts[i] || "0", 10);
    buf[8] = (port >> 8) & 0xff; buf[9] = port & 0xff;
    try { ws.write(buf); } catch {}
  }

  private cleanup(ws: any) {
    const tunnel = (ws as any)._tunnel as Tunnel | null;
    if (tunnel) try { tunnel.close(); } catch {}
    try { ws.end(); } catch {}
  }
}