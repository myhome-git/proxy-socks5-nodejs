#!/bin/bash
systemctl stop proxy-tcp.service
systemctl disable proxy-tcp.service
rm -f /etc/systemd/system/proxy-tcp.service
systemctl daemon-reload
echo "proxy-tcp.service 已移除"