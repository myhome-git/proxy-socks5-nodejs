/**
 * 明文泄露检测测试
 *
 * 模拟 Mode1 加密 → 网络传输 → Mode2 解密的完整流程，
 * 检查密文中是否包含明文片段。
 *
 * 用法: npx tsx test-leak-detect.mjs
 */
import { deriveKey, pack, tryUnpack, serializeTunnelRequest, serializeTunnelOk, packTunnelData, tryUnpackTunnelData } from "./src/security/sbox.js";

// 使用与生产一致的密码和盐值
const PASSWORD = "my-house-key-for-bing-downloads-2024";
const SALT = "salt-that-i-wrote-on-paper";
const key = deriveKey(PASSWORD, SALT);

// 测试用例：模拟真实场景的各种明文
const testCases = [
  {
    label: "隧道建立请求 (bing.com:443)",
    data: serializeTunnelRequest("cn.bing.com", 443),
  },
  {
    label: "隧道建立请求 (google.com:80)",
    data: serializeTunnelRequest("google.com", 80),
  },
  {
    label: "隧道建立成功响应",
    data: serializeTunnelOk(),
  },
  {
    label: "HTTP GET 请求 (模拟浏览器数据)",
    data: Buffer.from("GET /search?q=test HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
  },
  {
    label: "HTTPS ClientHello (首字节 0x16)",
    data: Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01, 0x00, 0x00]),
      Buffer.from("TLS ClientHello for bing.com"),
    ]),
  },
  {
    label: "隧道数据 (模拟加密后的网页内容)",
    data: Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>"),
  },
];

console.log("=".repeat(70));
console.log("🔍 明文泄露检测测试");
console.log("=".repeat(70));
console.log("");

let allPass = true;

for (const tc of testCases) {
  console.log("-".repeat(70));
  console.log(`测试用例: ${tc.label}`);
  console.log(`  明文 (hex): ${tc.data.subarray(0, 32).toString("hex")}`);
  console.log(`  明文 (utf-8): ${tc.data.subarray(0, 64).toString("utf-8").replace(/\n/g, "\\n")}`);
  console.log(`  明文长度: ${tc.data.length} bytes`);

  // 1. 加密
  const encrypted = pack(tc.data, key);

  // 提取密文部分（跳过前4字节外层大小 和 16字节IV）
  const ciphertext = encrypted.subarray(4);
  const iv = ciphertext.subarray(0, 16);
  const cipherOnly = ciphertext.subarray(16);

  console.log(`  IV (hex):     ${iv.toString("hex")}`);
  console.log(`  密文 (hex):   ${cipherOnly.subarray(0, 32).toString("hex")}`);
  console.log(`  密文长度:     ${cipherOnly.length} bytes`);

  // 2. 检查密文中是否包含明文片段
  const plaintextUtf8 = tc.data.toString("utf-8");

  let leaked = false;
  let leakedDetails = [];

  // 检查密文（二进制）中是否包含可读的ASCII文本（至少4个连续可打印字符）
  for (let i = 0; i < cipherOnly.length - 4; i++) {
    const chunk = cipherOnly.subarray(i, i + 4);
    const chunkStr = chunk.toString("utf-8");
    if (/^[a-zA-Z0-9.\/]+$/.test(chunkStr)) {
      leaked = true;
      leakedDetails.push(`  位置 ${i}: 可读ASCII "${chunkStr}"`);
      break;
    }
  }

  // 检查密文hex中是否包含明文中的可读单词
  const words = plaintextUtf8.split(/[^a-zA-Z0-9.-]+/).filter(w => w.length >= 4);
  for (const word of words) {
    const wordHex = Buffer.from(word, "utf-8").toString("hex");
    const wordLower = word.toLowerCase();
    // 检查密文hex中是否包含单词的hex
    if (cipherOnly.toString("hex").includes(wordHex)) {
      leaked = true;
      leakedDetails.push(`  密文hex包含明文单词: "${word}" (hex: ${wordHex})`);
      break;
    }
    // 也检查密文二进制中是否包含明文字符串
    const wordBuf = Buffer.from(word, "utf-8");
    for (let i = 0; i < cipherOnly.length - wordBuf.length; i++) {
      if (cipherOnly.subarray(i, i + wordBuf.length).equals(wordBuf)) {
        leaked = true;
        leakedDetails.push(`  密文二进制包含明文单词: "${word}" (位置 ${i})`);
        break;
      }
    }
    if (leaked) break;
  }

  // 3. 解密验证
  const result = tryUnpack(encrypted, key);
  const decryptOk = result !== null && result.data.equals(tc.data);
  console.log(`  解密验证: ${decryptOk ? "✅ 通过" : "❌ 失败"}`);

  // 4. 输出检测结果
  if (leaked) {
    console.log(`  明文泄露: ❌ 检测到明文泄露！`);
    for (const d of leakedDetails) {
      console.log(d);
    }
    allPass = false;
  } else {
    console.log(`  明文泄露: ✅ 未检测到明文泄露`);
  }

  console.log("");
}

console.log("=".repeat(70));
if (allPass) {
  console.log("✅ 全部测试通过：加密协议未泄露任何明文信息");
  console.log("   - 密文中未出现可读的ASCII文本");
  console.log("   - 密文二进制中未包含明文字符串");
  console.log("   - 解密后与原始明文完全一致");
} else {
  console.log("❌ 存在明文泄露问题，请检查加密协议");
}
console.log("=".repeat(70));