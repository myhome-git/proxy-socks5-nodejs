/**
 * HTTP 代理服务器
 *
 * 普通 HTTP 请求转发代理，支持 Mode2 请求头清洗。
 */
import { log, cleanForwardHeaders } from "../utils.js";

export class ProxyServer {
  /**
   * 处理 HTTP 请求
   * @param cleanHeaders 是否清洗请求头（Mode2 转发时设为 true）
   */
  async handleRequest(req: Request, cleanHeaders = false): Promise<Response> {
    const targetUrl = req.url;
    log(`收到请求: ${req.method} ${targetUrl}`);

    // 提取转发请求头
    let forwardHeaders: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      const lk = key.toLowerCase();
      if (!["host", "connection", "proxy-connection", "transfer-encoding", "keep-alive"].includes(lk)) {
        forwardHeaders[key] = value;
      }
    });

    // Mode2：清洗可能泄露用户信息的请求头
    if (cleanHeaders) {
      forwardHeaders = cleanForwardHeaders(forwardHeaders);
      log(`🧹 Mode2 已清洗请求头: ${targetUrl}`, "INFO");
    }

    // 普通转发（透传）— 流式返回，不缓存 body
    log(`普通转发: ${targetUrl}`);
    const resp = await fetch(targetUrl, {
      method: req.method,
      headers: forwardHeaders,
      body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
      signal: AbortSignal.timeout(30000),
    });

    // 构造响应头
    const responseHeaders = new Headers();
    resp.headers.forEach((value, key) => {
      const lk = key.toLowerCase();
      if (!["transfer-encoding", "keep-alive", "connection"].includes(lk)) {
        responseHeaders.set(key, value);
      }
    });

    return new Response(resp.body, {
      status: resp.status,
      headers: responseHeaders,
    });
  }
}