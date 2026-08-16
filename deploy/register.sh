#!/bin/bash
# 注册 systemd 服务（自动取当前目录作为 WORK_DIR）
WORK_DIR=$(pwd)
sed "s|{{WORK_DIR}}|$WORK_DIR|g" "$(dirname "$0")/proxy-tcp.service" | tee /etc/systemd/system/proxy-tcp.service > /dev/null
systemctl daemon-reload
systemctl enable proxy-tcp.service
echo "proxy-tcp.service 已注册，工作目录: $WORK_DIR"