/**
 * S-box 加密模块 (AES-256-CTR)
 *
 * 用于 Mode1 ↔ Mode2 之间的加密隧道通信。
 * 使用 AES-256-CTR 模式，Key 通过 PBKDF2 从密码派生。
 *
 * Wire format（零明文元数据）:
 *   [4字节: 加密块总大小] [16字节IV] [AES-256-CTR密文]
 *                                        ↑
 *                             密文内部 = [4字节: 原始数据长度] + [原始数据]
 *
 * 那4字节外层大小仅用于TCP流拆包，不暴露任何协议结构。
 */
import crypto from "crypto";

const IV_LENGTH = 16;
const KEY_LENGTH = 32; // AES-256
const ITERATIONS = 100000;
const DIGEST = "sha256";

/**
 * 从密码派生 AES-256 密钥
 */
export function deriveKey(password: string, salt: string): Buffer {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST);
}

/**
 * 加密数据 (AES-256-CTR)
 * 返回: [16字节IV][密文]
 */
export function encrypt(plaintext: Buffer | string, key: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
  const input = typeof plaintext === "string" ? Buffer.from(plaintext, "utf-8") : plaintext;
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  return Buffer.concat([iv, encrypted]);
}

/**
 * 解密数据 (AES-256-CTR)
 * 输入: [16字节IV][密文]
 * 返回: 明文 Buffer
 */
export function decrypt(data: Buffer, key: Buffer): Buffer {
  if (data.length < IV_LENGTH + 1) {
    throw new Error(`数据太短，无法解密: ${data.length} bytes`);
  }
  const iv = data.subarray(0, IV_LENGTH);
  const encrypted = data.subarray(IV_LENGTH);
  const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ============================================================
// 新的加密打包协议 — 零明文元数据
// ============================================================

/**
 * 打包加密数据（命令/响应帧）
 *
 * 内部结构（全部加密）:
 *   [4字节: 原始数据长度] + [原始数据]
 *
 * 外部结构:
 *   [4字节: 加密块总大小(仅用于TCP拆包)] + [IV] + [密文]
 */
export function pack(data: Buffer, key: Buffer): Buffer {
  // 内部: 4字节原始数据长度 + 原始数据
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const inner = Buffer.concat([lenBuf, data]);

  // 加密整个内部结构
  const encrypted = encrypt(inner, key);

  // 外部: 4字节加密块大小 + 加密数据
  const sizeBuf = Buffer.alloc(4);
  sizeBuf.writeUInt32BE(encrypted.length, 0);
  return Buffer.concat([sizeBuf, encrypted]);
}
/**
 * 解包解密数据
 *
 * 输入: [4字节: 加密块大小] + [IV] + [密文]
 * 返回: 原始数据
 */
export function unpack(packet: Buffer, key: Buffer): Buffer {
  // 跳过前4字节外层大小
  const encrypted = packet.subarray(4);
  // 解密
  const inner = decrypt(encrypted, key);
  // 读取前4字节原始数据长度
  const len = inner.readUInt32BE(0);
  return inner.subarray(4, 4 + len);
}

/**
 * 从缓冲区中提取第一个完整包
 * 用于TCP流式读取
 */
export function tryUnpack(buffer: Buffer, key: Buffer): { data: Buffer; consumed: number } | null {
  if (buffer.length < 4) return null;
  const totalLen = buffer.readUInt32BE(0);
  if (buffer.length < 4 + totalLen) return null;
  const packet = buffer.subarray(0, 4 + totalLen);
  const data = unpack(packet, key);
  return { data, consumed: 4 + totalLen };
}

/**
 * 打包隧道数据（直接加密原始字节，无内部长度包装）
 * 用于隧道模式下的数据流
 */
export function packTunnelData(data: Buffer, key: Buffer): Buffer {
  const encrypted = encrypt(data, key);
  const sizeBuf = Buffer.alloc(4);
  sizeBuf.writeUInt32BE(encrypted.length, 0);
  return Buffer.concat([sizeBuf, encrypted]);
}

/**
 * 从缓冲区中提取第一个隧道数据包
 */
export function tryUnpackTunnelData(buffer: Buffer, key: Buffer): { data: Buffer; consumed: number } | null {
  if (buffer.length < 4) return null;
  const totalLen = buffer.readUInt32BE(0);
  if (buffer.length < 4 + totalLen) return null;
  const encrypted = buffer.subarray(4, 4 + totalLen);
  const data = decrypt(encrypted, key);
  return { data, consumed: 4 + totalLen };
}

// ============================================================
// 序列化工具（用于命令帧的明文序列化，调用pack前使用）
// ============================================================

/**
 * 序列化HTTP请求
 */
export function serializeHttpRequest(method: string, url: string, headers: Record<string, string>, body?: Buffer): Buffer {
  return Buffer.from(
    `HTTP\n${method}\n${url}\n${JSON.stringify(headers)}\n${body ? body.toString("base64") : ""}`,
    "utf-8",
  );
}

/**
 * 序列化隧道建立请求
 */
export function serializeTunnelRequest(host: string, port: number): Buffer {
  return Buffer.from(`TUNNEL\n${host}\n${port}`, "utf-8");
}

/**
 * 序列化HTTP响应
 */
export function serializeHttpResponse(statusCode: number, headers: Record<string, string>, body?: Buffer): Buffer {
  return Buffer.from(
    `RESP\n${statusCode}\n${JSON.stringify(headers)}\n${body ? body.toString("base64") : ""}`,
    "utf-8",
  );
}

/**
 * 序列化隧道建立成功响应
 */
export function serializeTunnelOk(): Buffer {
  return Buffer.from("TUNNEL_OK", "utf-8");
}

/**
 * 序列化关闭命令
 */
export function serializeClose(): Buffer {
  return Buffer.from("CLOSE", "utf-8");
}

export interface ParsedHttpRequest {
  type: "http";
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Buffer;
}

export interface ParsedTunnelRequest {
  type: "tunnel";
  host: string;
  port: number;
}

export interface ParsedHttpResponse {
  type: "resp";
  statusCode: number;
  headers: Record<string, string>;
  body?: Buffer;
}

export interface ParsedTunnelOk {
  type: "tunnel_ok";
}

export interface ParsedClose {
  type: "close";
}

export type ParsedCommand = ParsedHttpRequest | ParsedTunnelRequest | ParsedHttpResponse | ParsedTunnelOk | ParsedClose;

/**
 * 解析命令帧
 */
export function parseCommand(data: Buffer): ParsedCommand {
  const text = data.toString("utf-8");
  const lines = text.split("\n");
  const type = lines[0] || "";

  switch (type) {
    case "HTTP": {
      const method = lines[1] || "";
      const url = lines[2] || "";
      const headers = JSON.parse(lines[3] || "{}");
      const bodyBase64 = lines.slice(4).join("\n");
      const body = bodyBase64 ? Buffer.from(bodyBase64, "base64") : undefined;
      return { type: "http", method, url, headers, body };
    }
    case "TUNNEL": {
      const host = lines[1] || "";
      const port = parseInt(lines[2] || "0", 10);
      return { type: "tunnel", host, port };
    }
    case "RESP": {
      const statusCode = parseInt(lines[1] || "200", 10);
      const headers = JSON.parse(lines[2] || "{}");
      const bodyBase64 = lines.slice(3).join("\n");
      const body = bodyBase64 ? Buffer.from(bodyBase64, "base64") : undefined;
      return { type: "resp", statusCode, headers, body };
    }
    case "TUNNEL_OK":
      return { type: "tunnel_ok" };
    case "CLOSE":
      return { type: "close" };
    default:
      throw new Error(`未知命令类型: ${type}`);
  }
}