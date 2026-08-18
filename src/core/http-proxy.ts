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
    createTunnel?: TunnelCreator,
  ) {
    this.createTunnel =
      createTunnel ||
      // 默认回退：直接 TCP 连接（不加密，仅用于无隧道场景）
      (async (host, port, firstData, onData, onClose) => {
        const socket = net.createConnection({ host, port }, () => {
          socket.write(firstData);
        });
        socket.on("data", onData);
        socket.on("close", onClose);
        socket.on("error", () => onClose());
        return {
          write: (d) => { try { socket.write(d); } catch {} },
          close: () => { try { socket.end(); } catch {} },
        };
      });
  }

  /**
   * 处理已连接的 Socket（用于统一代理服务器）
   * 接管该 Socket 的事件处理，执行 HTTP 代理逻辑
   */
  handleSocket(clientSocket: net.Socket, firstChunk?: Buffer): void {
    let state: "request" | "connect" | "forward" = "request";
    let targetHost = "";
    let targetPort = 0;
    let tunnel: Tunnel | null = null;
    let connecting = false;
    let connectBuffer = Buffer.alloc(0);
    let closed = false;

    const processData = async (data: Buffer) => {
      if (closed) return;

      if (state === "request") {
        // 解析 HTTP 请求行
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

          // 发送 200 响应，让浏览器开始发送数据
          try { clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); } catch {}
          state = "connect";
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
              (d) => { try { clientSocket.write(d); } catch {} },
              () => { try { clientSocket.end(); } catch {} },
            );
            state = "forward";
          } catch (err) {
            log(`HTTP 代理解析 URL 失败: ${url}`, "ERROR");
            try { clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n"); } catch {}
            try { clientSocket.end(); } catch {}
          }
        }
      } else if (state === "connect" && !connecting) {
        // CONNECT 后，浏览器发送 TLS 握手数据
        connecting = true;
        connectBuffer = Buffer.concat([connectBuffer, data]);

        try {
          tunnel = await this.createTunnel(
            targetHost,
            targetPort,
            connectBuffer,
            (d) => {
              if (closed) return;
              try { clientSocket.write(d); } catch {}
            },
            () => {
              if (closed) return;
              closed = true;
              try { clientSocket.end(); } catch {}
            },
          );
          state = "forward";
        } catch (err) {
          log(`HTTP CONNECT 隧道建立失败 ${targetHost}:${targetPort}`, "ERROR");
          closed = true;
          try { clientSocket.end(); } catch {}
        }
      } else if (state === "forward") {
        if (tunnel) {
          try { tunnel.write(data); } catch {}
        }
      }
    };

    clientSocket.on("data", processData);

    clientSocket.on("close", () => {
      if (closed) return;
      closed = true;
      if (tunnel) { try { tunnel.close(); } catch {} }
    });

    clientSocket.on("error", () => {
      if (closed) return;
      closed = true;
      if (tunnel) { try { tunnel.close(); } catch {} }
      try { clientSocket.end(); } catch {}
    });

    // 处理第一批数据
    if (firstChunk && firstChunk.length > 0) {
      processData(firstChunk);
    }
  }

  start(port: number, hostname = "127.0.0.1"): net.Server {
    const server = net.createServer((client) => {
      this.handleSocket(client);
    });

    server.listen(port, hostname, () => {
      log(`HTTP 代理已启动: ${hostname}:${port}`);
    });
    return server;
  }
}