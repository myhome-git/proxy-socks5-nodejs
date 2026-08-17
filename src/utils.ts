/**
 * 工具函数
 */
export function log(msg: string, level: "INFO" | "WARN" | "ERROR" = "INFO") {
    const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
    console.log(`[${ts}] [${level}] ${msg}`);
}

/**
 * 清洗转发请求头（Mode2 使用）
 * 移除可能泄露用户信息的请求头
 */
export function cleanForwardHeaders(headers: Record<string, string>): Record<string, string> {
    const cleaned: Record<string, string> = {};
    const forbiddenPrefixes = ["x-forwarded-", "via", "proxy-", "forwarded"];
    for (const [key, value] of Object.entries(headers)) {
        const lk = key.toLowerCase();
        let blocked = false;
        for (const prefix of forbiddenPrefixes) {
            if (lk.startsWith(prefix)) { blocked = true; break; }
        }
        if (!blocked) {
            cleaned[key] = value;
        }
    }
    return cleaned;
}