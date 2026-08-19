/**
 * 统一代理模式服务
 *
 * 根据配置运行 Mode1 / Mode2 的薄 facade。
 * 实际逻辑分别委托给 Mode1Handler 和 Mode2Handler。
 */
import { type AppConfig } from "../config.js";
import { deriveKey } from "../security/sbox.js";
import { Mode1Handler } from "./mode1-handler.js";
import { Mode2Handler } from "./mode2-handler.js";

export class ProxyModeServer {
    private handler: Mode1Handler | Mode2Handler;

    constructor(config: AppConfig) {
        const encryptKey = deriveKey(config.encryptPassword, config.encryptSalt);
        if (config.proxyMode === "mode1") {
            this.handler = new Mode1Handler(config, encryptKey);
        } else {
            this.handler = new Mode2Handler(config, encryptKey);
        }
    }

    start() {
        this.handler.start();
    }

    async stop() {
        await this.handler.stop();
    }
}
