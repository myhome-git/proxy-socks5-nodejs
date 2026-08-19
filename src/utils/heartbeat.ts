/**
 * 心跳检测类
 *
 * 自管理心跳开始/结束，外部只需提供 WebSocket 实例和心跳失败回调。
 * 支持指数退避重试，收到 pong 或 message 时自动重置失败计数。
 *
 * 使用方式：
 *   const hb = new HeartbeatOptions({ ws, onDead: () => ws.terminate() });
 *   // 无需手动管理开始/停止，构造即自动开始，WS 关闭时自动停止
 */
import { WebSocket } from "ws";

export interface HeartbeatOptionsConfig {
    ws: WebSocket;
    /** 心跳失败回调（连续失败达到 retryCount 次后调用） */
    onDead: () => void;
    /** 连续失败重试次数，默认 3 */
    retryCount?: number;
    /** 心跳超时时间（毫秒），即 Ping 间隔和 Pong 等待超时，默认 10000 (10s) */
    heartbeatTimeout?: number;
}

export class HeartbeatOptions {
    private ws: WebSocket;
    private onDead: () => void;
    private retryCount: number;
    private heartbeatTimeout: number;

    private failedCount = 0;
    private pingTimer: NodeJS.Timeout | null = null;
    private pongTimer: NodeJS.Timeout | null = null;
    private stopped = false;

    constructor(options: HeartbeatOptionsConfig) {
        this.ws = options.ws;
        this.onDead = options.onDead;
        this.retryCount = options.retryCount ?? 3;
        this.heartbeatTimeout = options.heartbeatTimeout ?? 10000;

        // 收到 pong：清除超时定时器、重置失败计数、重新调度下一次心跳
        this.ws.on("pong", () => {
            this.failedCount = 0;
            if (this.pongTimer) {
                clearTimeout(this.pongTimer);
                this.pongTimer = null;
            }
            this.schedulePing();
        });

        // 收到 message 说明对方还活着，同样重置并重新调度
        this.ws.on("message", () => {
            this.failedCount = 0;
            if (this.pongTimer) {
                clearTimeout(this.pongTimer);
                this.pongTimer = null;
            }
            this.schedulePing();
        });

        // WebSocket 关闭时自动停止心跳
        this.ws.on("close", () => this.stop());
        this.ws.on("error", () => this.stop());

        // 启动心跳
        this.schedulePing();
    }

    /**
     * 停止心跳，清理所有定时器
     */
    stop(): void {
        this.stopped = true;
        if (this.pingTimer) {
            clearTimeout(this.pingTimer);
            this.pingTimer = null;
        }
        if (this.pongTimer) {
            clearTimeout(this.pongTimer);
            this.pongTimer = null;
        }
    }

    /**
     * 安排下一次心跳
     */
    private schedulePing(interval?: number): void {
        if (this.stopped) return;

        // 清除可能残留的 pingTimer，避免重复调度
        if (this.pingTimer) {
            clearTimeout(this.pingTimer);
            this.pingTimer = null;
        }

        const delay = interval ?? this.heartbeatTimeout;
        this.pingTimer = setTimeout(() => {
            this.pingTimer = null;
            if (this.stopped) return;
            this.sendPing();
        }, delay);
    }

    /**
     * 发送 Ping 并启动 Pong 超时检测
     */
    private sendPing(): void {
        if (this.stopped) return;

        try {
            this.ws.ping();
        } catch {
            // WebSocket 已关闭，无需处理
            return;
        }

        // 清除可能残留的 pongTimer，避免重复超时检测
        if (this.pongTimer) {
            clearTimeout(this.pongTimer);
            this.pongTimer = null;
        }

        // 启动 Pong 超时检测
        this.pongTimer = setTimeout(() => {
            this.pongTimer = null;
            if (this.stopped) return;
            this.onPongTimeout();
        }, this.heartbeatTimeout);
    }

    /**
     * Pong 超时处理：失败计数递增，指数退避重试，达到阈值则调用 onDead
     */
    private onPongTimeout(): void {
        if (this.stopped) return;

        this.failedCount++;

        if (this.failedCount >= this.retryCount) {
            // 连续失败达到阈值，判定为僵尸连接
            this.stop();
            this.onDead();
            return;
        }

        // 指数退避：heartbeatTimeout × 2^(failedCount-1)
        const backoffInterval = this.heartbeatTimeout * Math.pow(2, this.failedCount - 1);
        this.schedulePing(backoffInterval);
    }
}