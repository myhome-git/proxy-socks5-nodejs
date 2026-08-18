/**
 * Mode1 加密端实现
 *
 * 统一 WebSocket 加密隧道模式。
 * 通过 SOCKS5 + HTTP 统一代理入口接收浏览器流量，
 * 全部通过 WebSocket 加密隧道转发到 Mode2。
 */
import net from "net";
import { WebSocket } from "ws";
import { type Tunnel } from "../core/socks5.js";
import { UnifiedProxyServer } from "../core/unified-proxy.js";
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
    private proxyServer: UnifiedProxyServer | null = null;
    private proxyServerInstance: net.Server | null = null;
    private config: AppConfig;
    private encryptKey: Buffer;

    constructor(config: AppConfig, encryptKey: Buffer) {
        this.config = config;
        this.encryptKey = encryptKey;
    }

    start() {
        this.proxyServerInstance = this.startUnifiedProxy();
    }

    async stop() {
        log("Mode1 正在关闭服务...", "INFO");
        if (this.proxyServer) {
            await this.proxyServer.stop();
            this.proxyServer = null;
        }
        this.proxyServerInstance = null;
        log("Mode1 服务已关闭", "INFO");
    }

    // ============================================================
    // 统一代理 — 单端口支持 SOCKS5 + HTTP 自动检测
    // 所有流量统一通过 WebSocket 加密隧道转发到 Mode2
    // ============================================================

    private startUnifiedProxy(): net.Server {
        const createTunnel = async (
            host: string, port: number,
            firstData: Buffer,
            onData: (data: Buffer) => void,
            onClose: () => void,
        ): Promise<Tunnel> => {
            const protocol = detectProtocol(firstData);
            log(`Mode1 [${protocol}] ${host}:${port} (${firstData.length} bytes)`);

            // 所有流量统一走 WebSocket 加密隧道
            return this.openWSTunnel(host, port, firstData, onData, onClose);
        };

        this.proxyServer = new UnifiedProxyServer(createTunnel);
        const server = this.proxyServer.start(this.config.proxyPort, this.config.bindHost);
        return server;
    }

    // ============================================================
    // WebSocket 加密隧道（所有流量统一使用）
    // ============================================================

    /**
     * 通过 WebSocket 连接 Mode2 建立加密隧道
     * 适用于 REMOTE_PROTOCOL=ws/wss 模式
     */
    private openWSTunnel(
        host: string, port: number,
        firstData: Buffer,
        onData: (data: Buffer) => void,
        onClose: () => void,
    ): Promise<Tunnel> {
        const wsProtocol = resolveWsProtocol(this.config); // "ws" or "wss"
        const wsUrl = `${wsProtocol}://${this.config.remoteHost}:${this.config.remotePort}/tunnel`;

        return new Promise((resolve, reject) => {
            const ws = new WebSocket(wsUrl);
            let established = false;
            let closed = false;
            // 缓存建立前的出站数据
            let pendingData: Buffer[] = [];

            const safeClose = () => {
                if (closed) return;
                closed = true;
                try { ws.close(); } catch {}
            };

            // 当 WebSocket 连接建立
            ws.on("open", () => {
                // 发送隧道建立请求
                const tunnelCmd = serializeTunnelRequest(host, port);
                const encrypted = pack(tunnelCmd, this.encryptKey);
                ws.send(encrypted);

                // 发送缓存的数据
                for (const d of pendingData) {
                    const encryptedData = packTunnelData(d, this.encryptKey);
                    ws.send(encryptedData);
                }
                pendingData = [];
            });

            // 收到 Mode2 回复
            ws.on("message", (data) => {
                const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);

                if (!established) {
                    // 尝试解析隧道建立响应
                    const result = tryUnpack(buf, this.encryptKey);
                    if (result) {
                        try {
                            const cmd = parseCommand(result.data);
                            if (cmd.type === "tunnel_ok") {
                                established = true;
                                log(`Mode1 WebSocket 隧道 ${host}:${port} 建立成功`);
                                // 发送第一包数据
                                if (firstData.length > 0) {
                                    const encryptedFirst = packTunnelData(firstData, this.encryptKey);
                                    ws.send(encryptedFirst);
                                }

                                const tunnel: Tunnel = {
                                    write: (d: Buffer) => {
                                        if (closed) return;
                                        const encryptedData = packTunnelData(d, this.encryptKey);
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
                    // 隧道建立后，所有消息都是隧道数据
                    const result = tryUnpackTunnelData(buf, this.encryptKey);
                    if (result) {
                        if (this.config.debugLog) {
                            log(`Mode1 收到响应内容 ${host}:${port} 解密（bytes）: ${result.data.length}`);
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
                    log(`Mode1 WebSocket 连接错误: ${err.message}`, "ERROR");
                    onClose();
                    reject(err);
                }
            });

            // 超时处理
            setTimeout(() => {
                if (!established && !closed) {
                    closed = true;
                    log(`Mode1 WebSocket 隧道建立超时: ${host}:${port}`, "WARN");
                    ws.close();
                    onClose();
                    reject(new Error("Tunnel establishment timeout"));
                }
            }, 30000);
        });
    }
}