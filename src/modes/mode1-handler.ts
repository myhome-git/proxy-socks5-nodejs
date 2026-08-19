/**
 * Mode1 加密端实现
 *
 * 统一代理入口 + WebSocket 加密隧道（隧道逻辑已封装在 UnifiedProxyServer 中）。
 * 此处仅为胶水配置层：读取配置，创建 UnifiedProxyServer，启动服务。
 */
import { UnifiedProxyServer } from "../core/unified-proxy.js";
import { log } from "../utils.js";
import { type AppConfig } from "../config.js";

export class Mode1Handler {
    private proxyServer: UnifiedProxyServer | null = null;
    private config: AppConfig;
    private encryptKey: Buffer;

    constructor(config: AppConfig, encryptKey: Buffer) {
        this.config = config;
        this.encryptKey = encryptKey;
    }

    start() {
        this.proxyServer = new UnifiedProxyServer({
            proxyPort: this.config.proxyPort,
            bindHost: this.config.bindHost,
            remoteHost: this.config.remoteHost,
            remotePort: this.config.remotePort,
            remoteProtocol: this.config.remoteProtocol,
            debugLog: this.config.debugLog,
            encryptKey: this.encryptKey,
        });
        this.proxyServer.start();
    }

    async stop() {
        log("Mode1 正在关闭服务...", "INFO");
        if (this.proxyServer) {
            await this.proxyServer.stop();
            this.proxyServer = null;
        }
        log("Mode1 服务已关闭", "INFO");
    }
}