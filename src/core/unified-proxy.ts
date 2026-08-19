/**
 * 统一代理服务器
 *
 * 在单个端口上同时支持 SOCKS5 和 HTTP 代理协议，
 * 并内置 WebSocket 加密隧道能力，直接连接远程 Mode2 解密端。
 *
 * 根据客户端首字节自动检测协议类型：
 *   0x05               => SOCKS5 代理
 *   'C'/'G'/'P'/'D'/'H'/'O'/'T' => HTTP 代理 (CONNECT/GET/POST/...)
 *   其他（如 0x16 TLS） => 拒绝连接
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
 * 客户端接入协议识别
 * 第一层：用户 Client 的连接方式
 * 
 * 根据首字节识别客户端通过什么协议接入代理：
 *   socks5 — 首字节 0x05（SOCKS5 协议版本号）
 *   http   — HTTP 方法首字母（C/CONNECT, G/GET, P/POST/PUT/PATCH, D/DELETE, H/HEAD, O/OPTIONS, T/TRACE）
 *   其他   — undefined（不支持，如 0x16 TLS/HTTPS 代理接入）
 * 
 * @param hexCode 首字节的十六进制字符串，例如 "0x05"
 * @returns "socks5" | "http" | undefined
 */
const PROTOCOL_CODE = {
    socks5: ['0x05'],
    http: ['0x43', '0x47', '0x50', '0x44', '0x48', '0x4f', '0x54'], // C G P D H O T
};

function detectProtocol(hexCode: string): "socks5" | "http" | undefined {
    if (PROTOCOL_CODE.socks5.includes(hexCode)) return "socks5";
    if (PROTOCOL_CODE.http.includes(hexCode)) return "http";
    return undefined;
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
    private wsConnections = new Set<WebSocket>();
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

                // 暂停 socket 流，防止在异步隧道建立期间数据丢失
                clientSocket.pause();

                // 根据首字节识别客户端接入协议（http / socks5）
                const firstByte = firstChunk[0]!;
                const hexByte = `0x${firstByte.toString(16).padStart(2, "0")}`;
                const protocol = detectProtocol(hexByte);

                if (this.config.debugLog) {
                    log(`统一代理: 检测到协议 ${protocol ?? "unknown"} (${hexByte})`);
                }

                if (protocol === "socks5") {
                    this.socks5Server.handleSocket(clientSocket, firstChunk);
                    clientSocket.resume(); // SOCKS5 自己管理数据流，需要恢复接收
                } else if (protocol === "http") {
                    this.httpProxyServer.handleSocket(clientSocket, firstChunk);
                    // http-proxy 会在隧道建立完成后在 startForwarding() 中调用 resume()
                } else {
                    // 无法识别的协议（包括 0x16 TLS/HTTPS 代理接入），安全关闭连接
                    this.sockets.delete(clientSocket);
                    clientSocket.destroy();
                    log(`统一代理: 无法识别的协议 (${hexByte})，连接已关闭`, "WARN");
                }
            });

            clientSocket.on("error", () => {
                this.sockets.delete(clientSocket);
                try { clientSocket.destroy(); } catch { }
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
            try { socket.destroy(); } catch { }
        }
        this.sockets.clear();

        // 关闭所有活跃的 WebSocket 隧道连接
        for (const ws of this.wsConnections) {
            try { ws.terminate(); } catch { }
        }
        this.wsConnections.clear();

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
    // WebSocket 加密隧道
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
            let connectTimer: NodeJS.Timeout | null = null;
            let responseTimer: NodeJS.Timeout | null = null;

            const safeClose = () => {
                if (closed) return;
                closed = true;
                if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
                if (responseTimer) { clearTimeout(responseTimer); responseTimer = null; }
                try { ws.close(); } catch { }
            };

            // 追踪 WebSocket 实例，用于 stop() 统一清理
            this.wsConnections.add(ws);
            ws.once("close", () => this.wsConnections.delete(ws));
            ws.once("error", () => this.wsConnections.delete(ws));

            ws.on("open", () => {
                // 连接已超时/出错，忽略此 open 事件
                if (closed) {
                    try { ws.close(); } catch { }
                    return;
                }
                if (connectTimer) clearTimeout(connectTimer);

                // 发送隧道建立命令（携带目标 host:port）
                const tunnelCmd = serializeTunnelRequest(host, port);
                const encrypted = pack(tunnelCmd, this.config.encryptKey);
                ws.send(encrypted);

                // 阶段 2：等待 tunnel_ok 超时（15s）
                responseTimer = setTimeout(() => {
                    if (!established && !closed) {
                        closed = true;
                        log(`Mode1 -> Mode2 隧道协商超时: ${host}:${port}`, "WARN");
                        safeClose();
                        onClose();
                        reject(new Error("Tunnel response timeout"));
                    }
                }, 15000);
            });

            ws.on("message", (data) => {
                // const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
                const buf = Buffer.isBuffer(data)
                    ? data
                    : Array.isArray(data)
                        ? Buffer.concat(data)
                        : Buffer.from(data);

                if (!established) {
                    const result = tryUnpack(buf, this.config.encryptKey);
                    if (result) {
                        try {
                            const cmd = parseCommand(result.data);
                            if (cmd.type === "tunnel_ok") {
                                established = true;
                                if (responseTimer) { clearTimeout(responseTimer); responseTimer = null; }
                                log(`Mode1 -> Mode2 连接成功 ${host}:${port}`);

                                if (firstData.length > 0) {
                                    const encryptedFirst = packTunnelData(firstData, this.config.encryptKey);
                                    ws.send(encryptedFirst);
                                    if (this.config.debugLog) {
                                        log(`Mode1 -> Mode2 首包数据 ${host}:${port} 原始（bytes）: ${firstData.length} 加密（bytes）: ${encryptedFirst.length}`);
                                    }
                                }

                                const tunnel: Tunnel = {
                                    write: (d: Buffer) => {
                                        if (closed) return;
                                        const encryptedData = packTunnelData(d, this.config.encryptKey);
                                        try {
                                            if (this.config.debugLog) {
                                                log(`Mode1 -> Mode2 数据 ${host}:${port} 原始（bytes）: ${d.length} 加密（bytes）: ${encryptedData.length}`);
                                            }
                                            ws.send(encryptedData);
                                        } catch { }
                                    },
                                    close: () => {
                                        safeClose();
                                        onClose();
                                    },
                                };

                                resolve(tunnel);
                                return;
                            }
                        } catch { }
                    }
                }

                if (established) {
                    const result = tryUnpackTunnelData(buf, this.config.encryptKey);
                    if (result) {
                        if (this.config.debugLog) {
                            log(`Mode1 <- Mode2 响应内容 ${host}:${port} 原始（bytes）: ${buf.length} 解密（bytes）: ${result.data.length}`);
                        }
                        onData(result.data);
                    } else {
                        // 无法解密的数据（可能被篡改或 Mode2 已失联），关闭隧道
                        log(`Mode1 <- Mode2 数据解密失败，关闭连接: ${host}:${port}`, "WARN");
                        safeClose();
                        onClose();
                    }
                }
            });

            ws.on("close", () => {
                if (!closed) {
                    closed = true;
                    onClose();
                }
                if (connectTimer) clearTimeout(connectTimer);
                if (responseTimer) clearTimeout(responseTimer);
            });

            ws.on("error", (err) => {
                if (!closed) {
                    closed = true;
                    log(`Mode1 -> Mode2 连接错误: ${err.message}`, "ERROR");
                    onClose();
                    reject(err);
                }
                if (connectTimer) clearTimeout(connectTimer);
                if (responseTimer) clearTimeout(responseTimer);
            });

            // 超时处理
            connectTimer = setTimeout(() => {
                if (!established && !closed) {
                    closed = true;
                    log(`Mode1 -> Mode2 隧道建立连接超时: ${host}:${port}`, "WARN");
                    try { ws.close(); } catch { }
                    onClose();
                    reject(new Error("Tunnel establishment timeout"));
                }
            }, 30000);
        });
    }
}