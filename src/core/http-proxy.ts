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
    let state: "request" | "forward" = "request";
    let targetHost = "";
    let targetPort = 0;
    let tunnel: Tunnel | null = null;
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

          // 提取 HTTP 头部结束后的 TLS 数据（浏览器可能在同一个 TCP 包中发送 TLS ClientHello）
          const headerEnd = data.indexOf("\r\n\r\n");
          let tlsData = Buffer.alloc(0);
          if (headerEnd !== -1 && headerEnd + 4 < data.length) {
            tlsData = Buffer.from(data.subarray(headerEnd + 4));
          }

          // 先创建隧道，确保隧道已就绪后再回复 200
          // 避免竞态条件：如果先回复 200，浏览器立即发送 TLS ClientHello，
          // 但隧道可能还没建好，导致 TLS 握手失败（ERR_SSL_PROTOCOL_ERROR）
          try {
            tunnel = await this.createTunnel(
              targetHost,
              targetPort,
              tlsData,
              (d) => { if (closed) return; try { clientSocket.write(d); } catch {} },
              () => { if (closed) return; closed = true; try { clientSocket.end(); } catch {} },
            );
            // 隧道已就绪，回复 200
            try { clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); } catch {}
            state = "forward";
          } catch (err) {
            log(`HTTP CONNECT 隧道建立失败 ${targetHost}:${targetPort}`, "ERROR");
            closed = true;
            try { clientSocket.end(); } catch {}
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