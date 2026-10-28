# Changelog

本项目版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.0] - 2026-10-28

### 功能
- 新增 `-6` 选项（缺省 1）：认证成功后自动催促 IPv6 配置（`reimpl/ipv6.c/h`）。
  收到 EAP Success 后非阻塞检测网卡地址，只有链路本地地址（`fe80::/10`）时
  在第 1/6/14 秒注入 ICMPv6 Router Solicitation（真实链路本地源，取不到时
  按 RFC 4861 用 `::` 且不带 SLLA），由内核完成 SLAAC/DHCPv6；仍无地址则
  后台调用系统续租兜底（Windows `ipconfig /renew6`，Linux `rdisc6`/
  `dhclient -6`/`dhcpcd -6`，macOS `ipconfig set <if> AUTOMATIC-V6`）；
  40 秒超时放弃。已配置地址判定覆盖全局单播与 ULA（`fc00::/7`），不局限于
  `2000::/3`。
- 地址检测跨平台实现：Windows `GetAdaptersAddresses`（按友好名/GUID 匹配
  pcap 设备），Linux/macOS `getifaddrs`。

### 变更
- Success 之后的周期性 Identity 保活心跳日志精简为点号，每 30 次打印一行
  `[hb] 已应答 N 次保活`，不再逐帧十六进制转储；握手阶段与 Failure、私有
  数据、重新认证挑战等报文仍完整打印。

### 验证
- 在真实 H3C 校园网（IPv6=有状态 DHCPv6，RA M=1/O=1）实测：清空 IPv6
  租约后认证，客户端自动发 RS 并在约 13 秒内完成 DHCPv6 四步交互拿到全局
  地址，ICMPv6/HTTPS 正常；已有地址时 1 秒内结束且不发送多余 RS。
- Linux clang 与 MinGW-w64 交叉编译均零警告；RS 帧校验和经独立校验。

### 背景
- 抓包确认该网络中官方 iNode 从不在 EAPOL 报文中携带任何 IP 地址，IPv6
  绑定由交换机监听 DHCPv6 交互生成，故不实现"在认证报文中上送 IPv6"。

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

[1.1.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.0
[1.0.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.0.0
