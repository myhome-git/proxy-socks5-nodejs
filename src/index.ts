/**
 * 并发加速代理 - 入口
 *
 * 支持双模式运行：
 *   Mode1 (加密端): 本地 HTTP/SOCKS5 代理，加密转发到 Mode2
 *   Mode2 (解密端): 远程解密转发服务器，清洗请求头后转发到目标
 */
import { loadConfig, printConfig, type AppConfig } from "./config.js";
import { log } from "./utils.js";
import { ProxyModeServer } from "./modes/proxy-modes.js";

const config: AppConfig = loadConfig();
printConfig(config);

const server = new ProxyModeServer(config);
server.start();

// 热更新 / 优雅关闭
async function shutdown() {
  log("正在关闭服务...", "INFO");
  // 设置超时：如果 5 秒内无法优雅关闭，强制退出进程释放端口
  const forceExit = setTimeout(() => {
    log("优雅关闭超时，强制退出进程", "WARN");
    process.exit(1);
  }, 5000);
  forceExit.unref(); // 不阻止进程退出

  await server.stop();
  clearTimeout(forceExit);
  log("服务已完全关闭", "INFO");
  // 确保进程退出，释放端口
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("SIGHUP", shutdown);
process.on("uncaughtException", (err) => {
  log("未捕获异常: " + err.message, "ERROR");
  console.error(err);
  // 发生未捕获异常时退出进程，确保端口释放
  process.exit(1);
});
