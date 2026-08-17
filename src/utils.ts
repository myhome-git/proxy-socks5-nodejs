/**
 * 工具函数
 */
export function log(msg: string, level: "INFO" | "WARN" | "ERROR" = "INFO") {
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  console.log(`[${ts}] [${level}] ${msg}`);
}

/**
 * 打印数据包的 hex 前缀（用于泄露检测）
 * 只打印前 maxBytes 字节，避免日志过长
 */
export function hexDump(label: string, buf: Buffer, maxBytes = 32) {
  const hex = buf.subarray(0, maxBytes).toString("hex");
  log(`[LEAK-DETECT] ${label}: ${hex} (${buf.length} bytes total)`);
}

/**
 * 清洗可能泄露用户真实信息的请求头
 * 用于 Mode2 解密后转发到真实目标之前
 */
export function cleanForwardHeaders(headers: Record<string, string>): Record<string, string> {
  const leakHeaders = new Set([
    // IP 泄露类
    "x-forwarded-for", "x-real-ip", "x-client-ip", "client-ip",
    "forwarded", "via", "x-proxy-user-ip", "cf-connecting-ip",
    "true-client-ip", "x-originating-ip", "x-forwarded-host",
    "x-forwarded-proto", "x-forwarded-port", "x-forwarded-server",
    "x-cluster-client-ip", "x-remote-ip", "x-remote-addr",
    "forwarded-for", "x-request-id",
    // 代理信息类
    "proxy-connection", "proxy-authorization", "proxy-authenticate",
    "x-cache", "x-cache-hit", "x-akamai-transformed",
  ]);

  const cleaned: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    const lk = key.toLowerCase();
    if (leakHeaders.has(lk)) {
      log(`🧹 清洗请求头: ${key}`, "INFO");
      continue; // 跳过泄露头
    }
    cleaned[key] = value;
  }

  return cleaned;
}