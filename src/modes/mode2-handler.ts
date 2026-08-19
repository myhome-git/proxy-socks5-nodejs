/**
 * Mode2 解密端实现
 *
 * 统一 WebSocket 隧道服务。
 * 接收 Mode1 的加密 WebSocket 连接，解密后 TCP 转发到目标网站。
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

export class Mode2Handler {
    private proxyServer: http.Server | null = null;
    private wss: WebSocketServer | null = null;
    private config: AppConfig;
    private encryptKey: Buffer;
    /** 活跃的目标 TCP 连接集合，stop() 时统一关闭 */
    private activeTargets = new Set<net.Socket>();
    /** 首消息超时（毫秒）：WS 连接建立后等待第一条隧道命令 */
    private static readonly FIRST_MESSAGE_TIMEOUT = 30000;

    constructor(config: AppConfig, encryptKey: Buffer) {
        this.config = config;
        this.encryptKey = encryptKey;
        this.config.encryptListenPort = parseInt(process.env.PORT || String(this.config.encryptListenPort), 10)
    }

    start() {
        const server = http.createServer();

        // 健康检查端点
        server.on("request", (req, res) => {
            if (req.url === "/health" || req.method === "GET") {
                res.writeHead(200, { "Content-Type": "text/plain" });
                res.end("OK");
            }
        });

        // WebSocket 隧道服务器
        const wss = new WebSocketServer({ server, path: "/tunnel" });
        wss.on("connection", (ws) => {
            this.handleWebSocket(ws);
        });
        this.wss = wss;

        // 使用云平台端口（PORT 环境变量）或配置端口
        const port = this.config.encryptListenPort;
        const host = this.config.encryptListenHost;

        server.listen(port, host, () => {
            log(`Mode2 服务器已启动: ${host}:${port}`);
            log(`  WebSocket 隧道路径: /tunnel`);
        });

        this.proxyServer = server;
    }

    async stop() {
        log("Mode2 正在关闭服务...", "INFO");
        if (this.wss) {
            // 强制关闭所有已建立的 WebSocket 连接
            for (const client of this.wss.clients) {
                try { client.terminate(); } catch { }
            }
            this.wss.close();
            this.wss = null;
        }
        // 强制关闭所有目标 TCP 连接
        for (const target of this.activeTargets) {
            try { target.destroy(); } catch { }
        }
        this.activeTargets.clear();
        if (this.proxyServer) {
            await new Promise<void>((resolve) => {
                this.proxyServer!.close(() => resolve());
                this.proxyServer!.unref();
            });
            this.proxyServer = null;
        }
        log("Mode2 服务已关闭", "INFO");
    }

    // ============================================================
    // WebSocket 隧道处理
    // ============================================================

    private handleWebSocket(ws: WebSocket) {
        log("Mode2 WebSocket 隧道连接建立");

        // 首消息超时保护：客户端连接后必须在规定时间内发送有效的隧道建立请求，
        // 否则视为僵尸连接强制关闭，防止资源泄漏
        const firstMessageTimer = setTimeout(() => {
            log("Mode2 WS 首消息超时，关闭连接", "WARN");
            try { ws.close(); } catch { }
        }, Mode2Handler.FIRST_MESSAGE_TIMEOUT);

        // 等待第一条加密消息 (隧道建立请求)
        ws.once("message", (data) => {
            clearTimeout(firstMessageTimer);
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

        ws.on("error", () => { });
    }

    /**
     * 连接到目标服务器，并处理双向加密转发
     */
    private connectTarget(ws: WebSocket, host: string, port: number) {

        let closed = false;
        // 缓存建立连接前收到的隧道数据
        let pendingData: Buffer[] = [];
        let targetConn: net.Socket | null = null;

        const target = net.createConnection({ host, port }, () => {
            log(`Mode2 目标连接成功: ${host}:${port}`);

            // 发送隧道建立成功响应
            try {
                ws.send(pack(serializeTunnelOk(), this.encryptKey));
            } catch { }

            // 发送缓存的隧道数据
            for (const d of pendingData) {
                try { target.write(d); } catch { }
            }
            pendingData = [];
        });

        // 跟踪目标连接，stop() 时统一关闭
        this.activeTargets.add(target);
        target.on("close", () => {
            this.activeTargets.delete(target);
        });
        target.on("error", () => {
            this.activeTargets.delete(target);
        });

        // 目标 → 加密 → Mode1
        target.on("data", (targetData) => {
            if (closed) return;
            const encrypted = packTunnelData(targetData, this.encryptKey);
            if (this.config.debugLog) {
                log(`Mode2 收到响应内容 ${host}:${port} tcp 原始（bytes）: ${targetData.length}  加密（bytes）: ${encrypted.length}`);
            }
            try { ws.send(encrypted); } catch { }
        });

        target.on("close", () => {
            if (closed) return;
            closed = true;
            try {
                ws.send(pack(serializeClose(), this.encryptKey));
            } catch { }
            try { ws.close(); } catch { }
        });

        target.on("error", (err) => {
            if (closed) return;
            closed = true;
            log(`目标连接错误 ${host}:${port} - ${err.message}`, "ERROR");
            // 如果目标连接失败，通知 Mode1
            try {
                ws.send(pack(serializeClose(), this.encryptKey));
            } catch { }
            try { ws.close(); } catch { }
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
                    try { target.write(result.data); } catch { }
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
            try { target.end(); } catch { }
        });

        ws.on("error", () => {
            if (closed) return;
            closed = true;
            try { target.end(); } catch { }
        });

        // 超时处理
        target.setTimeout(300000, () => {
            if (closed) return;
            closed = true;
            log(`Mode2 隧道超时: ${host}:${port}`, "WARN");
            try { target.end(); } catch { }
            try { ws.close(); } catch { }
        });

        targetConn = target;
    }

    getServer() {
        return this.proxyServer
    }
}