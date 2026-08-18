/**
 * 统一代理服务器
 *
 * 在单个端口上同时支持 SOCKS5 和 HTTP 代理协议。
 * 根据客户端首字节自动检测协议类型：
 *   0x05 → SOCKS5 代理
 *   其他 → HTTP 代理 (GET/POST/CONNECT)
 *
 * 这样客户端只需配置一个代理端口（如 1080），
 * 无论是 SOCKS5 还是 HTTP 协议都能正常工作。
 */
import net from "net";
import { log } from "../utils.js";
import { Socks5Server, type Tunnel, type TunnelCreator } from "./socks5.js";
import { HttpProxyServer } from "./http-proxy.js";

/**
 * 检测代理协议类型
 * @param firstByte 客户端发送的第一个字节
 * @returns "socks5" 或 "http"
 */
function detectProxyProtocol(firstByte: number): "socks5" | "http" {
  // SOCKS5 协议首字节固定为 0x05
  if (firstByte === 0x05) return "socks5";
  return "http";
}

/**
 * 统一代理服务器
 * 在单个端口上自动检测并处理 SOCKS5 和 HTTP 代理协议
 */
export class UnifiedProxyServer {
  private socks5Server: Socks5Server;
  private httpProxyServer: HttpProxyServer;
  private server: net.Server | null = null;
  private sockets = new Set<net.Socket>();

  constructor(private createTunnel: TunnelCreator) {
    this.socks5Server = new Socks5Server(createTunnel);
    this.httpProxyServer = new HttpProxyServer(createTunnel);
  }

  /**
   * 启动统一代理服务器
   * @param port 监听端口
   * @param hostname 监听地址
   */
  start(port: number, hostname = "127.0.0.1"): net.Server {
    const server = net.createServer((clientSocket) => {
      this.sockets.add(clientSocket);
      clientSocket.once("close", () => this.sockets.delete(clientSocket));

      // 等待接收第一个字节，用于协议检测
      clientSocket.once("data", (firstChunk) => {
        if (firstChunk.length === 0) {
          clientSocket.end();
          return;
        }

        const firstByte = firstChunk[0]!;
        const protocol = detectProxyProtocol(firstByte);

        if (this.createTunnel.toString().includes("mode1") || this.createTunnel.toString().includes("Mode1")) {
          log(`统一代理: 检测到协议 ${protocol} (0x${firstByte.toString(16)})`);
        }

        // 移除 once(data) 监听器，将控制权移交给具体协议处理器
        if (protocol === "socks5") {
          // SOCKS5 代理：移交 Socks5Server.handleSocket
          this.socks5Server.handleSocket(clientSocket, firstChunk);
        } else {
          // HTTP 代理：移交 HttpProxyServer.handleSocket
          this.httpProxyServer.handleSocket(clientSocket, firstChunk);
        }
      });

      // 如果客户端在发送数据前就断开连接
      clientSocket.on("error", () => {
        this.sockets.delete(clientSocket);
        try { clientSocket.destroy(); } catch {}
      });
    });

    server.listen(port, hostname, () => {
      log(`统一代理服务器已启动: ${hostname}:${port} (SOCKS5 + HTTP)`);
    });

    this.server = server;
    return server;
  }

  /**
   * 停止服务器
   */
  async stop(): Promise<void> {
    if (!this.server) return;

    // 关闭所有活跃连接
    for (const socket of this.sockets) {
      try { socket.destroy(); } catch {}
    }
    this.sockets.clear();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
        this.server.unref();
      } else {
        resolve();
      }
    });
  }
}