# 重构任务清单

- [x] 安装 ws + @types/ws 依赖
- [ ] 重写 mode2-handler.ts：net.createServer → http.createServer + WebSocketServer
- [ ] 重写 mode1-handler.ts：协议检测 + 分层传输
- [ ] 修改 socks5.ts：支持延迟建立隧道
- [ ] 修改 config.ts：简化配置
- [ ] 编译测试