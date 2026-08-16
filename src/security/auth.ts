/**
 * 认证模块
 *
 * 支持 HTTP Proxy Basic Auth 和 SOCKS5 用户名/密码认证。
 * 用户名和密码都使用配置中的值（默认 admin/admin）。
 */
import { log } from "../utils.js";

/**
 * 验证 HTTP Proxy-Authorization Basic 认证
 * 格式: "Basic base64(username:password)"
 */
export function checkHttpAuth(
  proxyAuth: string | undefined | null,
  expectedUser: string,
  expectedPass: string,
): boolean {
  if (!proxyAuth) {
    return false;
  }

  const parts = proxyAuth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Basic") {
    return false;
  }

  try {
    const decoded = atob(parts[1] || "");
    const colonIdx = decoded.indexOf(":");
    if (colonIdx === -1) return false;
    const user = decoded.slice(0, colonIdx);
    const pass = decoded.slice(colonIdx + 1);
    return user === expectedUser && pass === expectedPass;
  } catch {
    return false;
  }
}

/**
 * 生成 HTTP 407 Proxy Authentication Required 响应
 */
export function proxyAuthRequiredResponse(): Response {
  return new Response("Proxy Authentication Required", {
    status: 407,
    headers: {
      "Proxy-Authenticate": 'Basic realm="Proxy"',
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

/**
 * SOCKS5 用户名/密码认证 (RFC 1929)
 *
 * 协商子协商:
 * 客户端: [0x01, 用户名长度, 用户名, 密码长度, 密码]
 * 服务端: [0x01, 状态码]  (0x00 = 成功, 0x01 = 失败)
 */
export function checkSocks5UserPassAuth(
  data: Buffer,
  expectedUser: string,
  expectedPass: string,
): { success: boolean; response: Buffer } {
  if (data.length < 5) {
    return { success: false, response: Buffer.from([0x01, 0x01]) };
  }

  const ver = data[0];
  if (ver !== 0x01) {
    return { success: false, response: Buffer.from([0x01, 0x01]) };
  }

  const ulen = data[1];
  if (ulen === undefined || data.length < 2 + ulen + 1) {
    return { success: false, response: Buffer.from([0x01, 0x01]) };
  }

  const username = data.slice(2, 2 + ulen).toString("utf-8");
  const plen = data[2 + ulen];
  if (plen === undefined || data.length < 2 + ulen + 1 + plen) {
    return { success: false, response: Buffer.from([0x01, 0x01]) };
  }

  const password = data.slice(2 + ulen + 1, 2 + ulen + 1 + plen).toString("utf-8");

  const success = username === expectedUser && password === expectedPass;
  if (!success) {
    log(`SOCKS5 认证失败: 用户名="${username}"`, "WARN");
  }

  return {
    success,
    response: Buffer.from([0x01, success ? 0x00 : 0x01]),
  };
}