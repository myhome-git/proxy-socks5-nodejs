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

/**
 * Node.js 版本检测
 * ws 模块和 esbuild 编译目标要求 Node.js 20+，低版本无法正常运行
 */
const REQUIRED_NODE_MAJOR = 20;
const nodeMajor = parseInt(`${process.versions.node ?? "0"}`.split(".")[0] ?? "0", 10);
if (nodeMajor < REQUIRED_NODE_MAJOR) {
    log(`当前 Node.js 版本 ${process.versions.node} 过低，本项目要求 Node.js ${REQUIRED_NODE_MAJOR}+`, "ERROR");
    log(`ws 模块和构建产物依赖 Node.js 20+ 特性，请升级 Node.js：https://nodejs.org/`, "ERROR");
    process.exit(1);
}

log("正在启动服务...", "INFO");

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
