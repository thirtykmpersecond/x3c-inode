# Changelog

本项目版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-08-25

首个公开版本。

### 功能
- H3C/iNode 802.1X 认证客户端，跨平台支持 Linux / macOS / Windows。
- 支持标准 EAP-MD5（type 0x04）与 H3C 私有 EAP type 0x07 明文密码。
- H3C 私有版本区：双重 XOR + Base64 编码（`fill_client_version_area`）。
- 原厂固件版全部命令行参数：`-u -p -I -x -m -i -v -A -P -M -V`。
- V7 版本串分隔符 `0x11` 的命令行 `\xNN` 转义。
- EAPOL-Start/Logoff 发往 H3C 私有多播 `01:d0:f8:00:00:03` 并补零。
- 排障选项：`-l` 枚举网卡、`-S` 只监听抓包、`-d` 十六进制转储、`-L` 写日志。
- Ctrl-C 自动发送 EAPOL-Logoff 再退出。

### 平台
- **Windows x64**：经 Npcap 收发二层帧，自带 getopt_long 兼容层，已实网认证成功。
- **macOS**：getifaddrs 取地址、BPF 抓包，已实网认证成功。
- **Linux**：ioctl 取地址、libpcap 抓包，已编译通过。

### 工具
- `scripts/decode_version.py`：反解 Base64 版本区，定位服务器接受的版本串。

### 已知限制
- H3C 私有保活包（特征 `19 2b 44 2b 32`，需 3DES + 双 MD5 挑战应答）未实现；
  在启用保活的网络可能长时间运行后掉线。
- `-M 1`（部分高校变体）为推测实现，未经实网验证。
- Linux 分支未经真实 H3C 网络验证。

[1.0.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.0.0
