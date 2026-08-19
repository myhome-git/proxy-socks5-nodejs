/**
 * HTTP 代理服务器 (CONNECT + 普通HTTP)
 *
 * 支持：
 *   - CONNECT 方法 (HTTPS 隧道)
 *   - 普通 HTTP 请求 (GET/POST 等，通过隧道转发)
 *
 * 与 SOCKS5 代理使用相同的隧道创建接口，共享加密隧道逻辑。
 */
import net from "net";
import { log } from "../utils.js";
import { type Tunnel, type TunnelCreator } from "./socks5.js";

/**
 * HTTP 代理服务器
 */
export class HttpProxyServer {
    private createTunnel: TunnelCreator;

    constructor(
        createTunnel: TunnelCreator,
    ) {
        this.createTunnel = createTunnel;
    }

    /**
     * 处理已连接的 Socket（用于统一代理服务器）
     * 接管该 Socket 的事件处理，执行 HTTP 代理逻辑
     */
    handleSocket(clientSocket: net.Socket, firstChunk?: Buffer): void {
        let targetHost = "";
        let targetPort = 0;
        let tunnel: Tunnel | null = null;
        let closed = false;

        // 隧道建立完成后，注册 data 事件开始转发，恢复 socket 流
        const startForwarding = () => {
            clientSocket.on("data", (data) => {
                if (closed || !tunnel) return;
                try { tunnel.write(data); } catch { }
            });
            clientSocket.resume();
        };

        // 处理初始请求（同步解析，异步建隧道）
        const processInitialRequest = async (data: Buffer) => {
            const text = data.toString("utf-8");
            const lines = text.split("\r\n");
            const requestLine = lines[0] || "";
            const parts = requestLine.split(" ");
            const method = parts[0] || "";
            const url = parts[1] || "";

            if (method === "CONNECT") {
                // CONNECT host:port HTTP/1.1
                const addr = url.split(":");
                targetHost = addr[0] || "";
                targetPort = parseInt(addr[1] || "443", 10);
                log(`HTTP CONNECT: ${targetHost}:${targetPort}`);

                // 提取 HTTP 头部结束后的 TLS 数据（浏览器可能在同一个 TCP 包中发送 TLS ClientHello）
                const headerEnd = data.indexOf("\r\n\r\n");
                let tlsData = Buffer.alloc(0);
                if (headerEnd !== -1 && headerEnd + 4 < data.length) {
                    tlsData = Buffer.from(data.subarray(headerEnd + 4));
                }

                try {
                    tunnel = await this.createTunnel(
                        targetHost,
                        targetPort,
                        tlsData,
                        (d) => { if (closed) return; try { clientSocket.write(d); } catch { } },
                        () => { if (closed) return; closed = true; try { clientSocket.end(); } catch { } },
                    );
                    // 客户端可能在隧道建立期间已关闭，避免孤儿隧道
                    if (closed || clientSocket.destroyed) {
                        log(`HTTP CONNECT 客户端已关闭，关闭隧道: ${targetHost}:${targetPort}`, "WARN");
                        try { tunnel.close(); } catch { }
                        return;
                    }
                    // 隧道已就绪，回复 200
                    try { clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); } catch { }
                    startForwarding();
                } catch (err) {
                    log(`HTTP CONNECT 隧道建立失败 ${targetHost}:${targetPort}`, "ERROR");
                    closed = true;
                    try { clientSocket.end(); } catch { }
                }
            } else {
                // 普通 HTTP 请求 (GET/POST 等)
                try {
                    const parsedUrl = new URL(url);
                    targetHost = parsedUrl.hostname;
                    targetPort = parseInt(parsedUrl.port || "80", 10);
                    log(`HTTP ${method}: ${targetHost}:${targetPort}${parsedUrl.pathname}`);

                    // 创建隧道，将完整 HTTP 请求作为 firstData 发送
                    tunnel = await this.createTunnel(
                        targetHost,
                        targetPort,
                        data,
                        (d) => { try { clientSocket.write(d); } catch { } },
                        () => { try { clientSocket.end(); } catch { } },
                    );
                    // 客户端可能在隧道建立期间已关闭，避免孤儿隧道
                    if (closed || clientSocket.destroyed) {
                        log(`HTTP 客户端已关闭，关闭隧道: ${targetHost}:${targetPort}`, "WARN");
                        try { tunnel.close(); } catch { }
                        return;
                    }
                    startForwarding();
                } catch (err) {
                    log(`HTTP 代理解析 URL 失败: ${url}`, "ERROR");
                    try { clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n"); } catch { }
                    try { clientSocket.end(); } catch { }
                }
            }
        };

        // 处理第一批数据
        if (firstChunk && firstChunk.length > 0) {
            processInitialRequest(firstChunk);
        }

        clientSocket.on("close", () => {
            if (closed) return;
            closed = true;
            if (tunnel) { try { tunnel.close(); } catch { } }
        });

        clientSocket.on("error", () => {
            if (closed) return;
            closed = true;
            if (tunnel) { try { tunnel.close(); } catch { } }
            try { clientSocket.end(); } catch { }
        });
    }

    start(port: number, hostname: string): net.Server {
        const server = net.createServer((client) => {
            this.handleSocket(client);
        });

        server.listen(port, hostname, () => {
            log(`HTTP 代理已启动: ${hostname}:${port}`);
        });
        return server;
    }
}