# Lan Scanner Dashboard 🔍

一款运行在 Docker 中的轻量级局域网服务扫描仪，支持服务识别、一键跳转和自定义备注。

## ✨ 特性
- **一键扫描**：自动探测局域网在线设备及开放端口（支持自定义网段）
- **智能识别**：自动识别常见服务（HTTP/HTTPS/SSH/MySQL 等）
- **点击跳转**：点击端口号直接在新标签页打开对应服务
- **备注持久化**：可为任意 IP+端口 添加备注，数据保存在 SQLite 中，重启不丢失
- **开箱即用**：基于 Docker Compose，一键构建启动

## 🚀 快速开始

### 1. 克隆仓库
bash
git clone [你的仓库地址]](https://github.com/AnAnLikeMe/lan-scanner)
cd lan-scanner
