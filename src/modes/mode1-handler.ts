/**
 * Mode1 加密端实现
 *
 * 仅 SOCKS5 入口，接收 Proxifier 转发的所有流量。
 * 收到浏览器第一批数据后检测协议类型，统一通过 WebSocket 加密隧道转发到 Mode2。
 */
import net from "net";
import { WebSocket } from "ws";
import { Socks5Server, type Tunnel } from "../core/socks5.js";
import { HttpProxyServer } from "../core/http-proxy.js";
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
 * 生成数据前 N 字节的十六进制预览字符串
 */
function hexPreview(data: Buffer, maxBytes: number = 32): string {
  const len = Math.min(data.length, maxBytes);
  const hex = data.subarray(0, len).toString("hex").toUpperCase();
  return hex;
}

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

    // HTTP 响应
    if (head.startsWith("http/")) return "http";

    // 其他协议
    return "tcp";
}

export class Mode1Handler {
    private socks5Server: Socks5Server | null = null;
    private socks5ServerInstance: net.Server | null = null;
    private socks5Sockets = new Set<net.Socket>();
    private httpProxyServer: HttpProxyServer | null = null;
    private httpProxyServerInstance: net.Server | null = null;
    private httpProxySockets = new Set<net.Socket>();
    private config: AppConfig;
    private encryptKey: Buffer;

    constructor(config: AppConfig, encryptKey: Buffer) {
        this.config = config;
        this.encryptKey = encryptKey;
    }

    start() {
        this.socks5ServerInstance = this.startSocks5();
        this.httpProxyServerInstance = this.startHttpProxy();
    }

    async stop() {
        log("Mode1 正在关闭服务...", "INFO");
        if (this.socks5ServerInstance) {
            await this.closeServerForce(this.socks5ServerInstance, this.socks5Sockets);
            this.socks5ServerInstance = null;
        }
        if (this.httpProxyServerInstance) {
            await this.closeServerForce(this.httpProxyServerInstance, this.httpProxySockets);
            this.httpProxyServerInstance = null;
        }
        this.socks5Server = null;
        this.httpProxyServer = null;
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
            return this.openTunnel(host, port, protocol, firstData, onData, onClose);
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
    // HTTP 代理 — 方案 B，与 SOCKS5 分开监听
    // ============================================================

    private startHttpProxy(): net.Server {
        const createTunnel = async (
            host: string, port: number,
            firstData: Buffer,
            onData: (data: Buffer) => void,
            onClose: () => void,
        ): Promise<Tunnel> => {
            const protocol = detectProtocol(firstData);
            log(`Mode1 HTTP [${protocol}] ${host}:${port} (${firstData.length} bytes)`);

            // 所有协议统一通过 WebSocket 加密隧道
            return this.openTunnel(host, port, protocol, firstData, onData, onClose);
        };

        this.httpProxyServer = new HttpProxyServer(createTunnel);
        const server = this.httpProxyServer.start(this.config.httpProxyPort, this.config.bindHost);
        server.on("connection", (socket) => {
            this.httpProxySockets.add(socket);
            socket.on("close", () => this.httpProxySockets.delete(socket));
        });
        return server;
    }

    // ============================================================
    // WebSocket 加密隧道 — 统一通道
    // ============================================================

    private openTunnel(
        host: string, port: number,
        protocol: DetectedProtocol,
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
                ws.send(pack(tunnelReq, this.encryptKey));
            };

            // 统一消息处理：用消息格式（pack vs packTunnelData）区分控制消息和数据，不依赖消息顺序
            ws.onmessage = (event) => {
                const raw = Buffer.isBuffer(event.data) ? event.data : Buffer.from(event.data as ArrayBuffer);

                // 1) 先尝试解析为控制消息（pack 格式，带命令头）
                const unpacked = tryUnpack(raw, this.encryptKey);
                if (unpacked) {
                    let cmd;
                    try { cmd = parseCommand(unpacked.data); } catch { /* 不是命令，按数据走 */ }
                    if (cmd?.type === 'tunnel_ok' && !settled) {
                        settled = true;

                        const tunnel: Tunnel = {
                            write: (d: Buffer) => {
                                const encrypted = packTunnelData(d, this.encryptKey);
                                if (this.config.debugLog) {
                                    log(`Mode1 收到请求内容 ${host}:${port} ${protocol} 原始（bytes）: ${d.length}  加密（bytes）: ${encrypted.length}`);
                                }
                                try { ws.send(encrypted); } catch {}
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
                        return;
                    }
                    // 其他控制命令可以扩展
                }

                // 2) 不是控制消息，尝试解析为隧道数据（packTunnelData 格式）
                const r = tryUnpackTunnelData(raw, this.encryptKey);
                if (r) {
                    if (!settled) {
                        // 隧道还没建立就收到数据？丢弃
                        return;
                    }
                    if (this.config.debugLog) {
                        log(`Mode1 收到响应内容 ${host}:${port} ${protocol} 原始（bytes）: ${raw.length}  解密（bytes）: ${r.data.length}`);
                    }
                    try { onData(r.data); } catch {}
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
                    try { sock.destroy(); } catch { }
                }
                sockets.clear();
            }
            server.close(() => { resolve(); });
            server.unref();
            setTimeout(() => resolve(), 3000);
        });
    }

}