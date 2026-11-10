# Changelog

本项目版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.2-rc.1] - 2026-11-10

### 修复（OpenWrt 实测）
- **v6kick 等待窗口对嵌入式 DHCPv6 客户端过短**：OpenWrt 的 odhcp6c 在
  802.1X 认证放行前发出的 RS/DHCPv6 请求会被端口丢弃，随后进入指数退避；
  认证成功后其 DHCPv6 交互可能超过 40 秒才完成，而旧版固定 40 秒即报
  "该网络可能未部署 IPv6" 并停止催促（实测地址稍后确实由 odhcp6c 正常
  获取，属于误报）。现：
  - 检测到系统 DHCPv6 客户端（UDP 546 被占用）时，放弃阈值从 40 秒
    **放宽到 180 秒**，到期提示语改为"停止催促，系统客户端会继续自行
    获取"，不再误报网络未部署 IPv6；无系统客户端时维持 40 秒；
  - 初始三帧 RS（1/6/14 秒）之后，**等待期内每 20 秒补发一帧 RS**，
    避免网关长时间收不到 RS 而不推 RA；
  - `x3c_v6kick_t` 增加 `sys_client` 状态，记录 546 探测结果。

### 工程
- CI 新增 `build-openwrt-armv7` job：musl.cc `arm-linux-musleabihf` 交叉
  工具链 + 源码静态编译 libpcap，产出 musl 全静态 ARMv7 二进制
  `x3c8021x-re-openwrt-armv7`（硬浮点 EABIhf，适用 ipq40xx/mvebu/sunxi/
  armsr 等目标，路由器无需 opkg 装 libpcap），Release 附件由 4 个增至 5 个。

### 验证
- 桩模块单测（假 pcap + 真实单调时钟/getifaddrs）：无 546 监听时
  RS 节奏 1/6/14/34 秒、40 秒 FAIL；模拟 546 占用时正确识别系统客户端、
  46 秒内保持 ACTIVE 不超时、不启动竞争进程；
- ARMv7 交叉编译在本机按 CI 同款步骤实测通过（ELF 32-bit ARM EABI5，
  static-pie，strip 后约 305 KB）；glibc `-Wall -Wextra` 零警告。

## [1.1.1] - 2026-11-05

跨平台稳定性修复版本，经 Windows 实网与 Ubuntu Live（musl 全静态二进制）
实测验证。建议所有用户升级。

### 修复
- **修复 macOS / 新版 Linux 认证成功后反复全量重认证**。原代码把"连续 15 次
  `pcap_next_ex` 读超时无报文"当作掉线判据，但零流量时的 libpcap 读超时是
  平台相关行为：macOS BPF、Linux TPACKET_V2 到点返回 0；而 Linux
  TPACKET_V3（libpcap ≥ 1.5 默认，实测 1.10.4 零流量阻塞超过 8 秒）与
  Windows Npcap 在首帧到来前定时器不走、可能无限阻塞。结果同一判据在部分
  平台每 ~15 秒误判掉线，在另一些平台则永远检测不到真掉线。
  新增 `x3c_wait_frame()`（`reimpl/x3c.c`）自持 1 秒粒度计时：POSIX 用
  `pcap_get_selectable_fd()` + `poll()`，Windows 用 `pcap_getevent()` +
  `WaitForSingleObject()`，三平台行为一致；取不到可等待句柄时才退回
  `pcap_next_ex`（注释注明该退化路径）。
- **修复 Windows/Npcap 报文延迟数分钟的回归**：使用 event 等待必须先
  `pcap_setmintocopy(h, 0)`，否则内核缓冲默认攒满 16KB 才置位读事件，
  60 字节的稀疏 EAPOL 帧会被拖延数分钟。认证与 `-S` 监听两处打开句柄后
  均已设置。
- **IPv6 催促计时改用单调时钟**（`reimpl/ipv6.c`）：原用 `time(NULL)`，
  在 NTP 对时回拨墙上时钟的机器上（如双系统 Live 环境）会出现
  `用时 -28779s` 且后续 RS/续租/放弃调度静默失效。现 POSIX 用
  `clock_gettime(CLOCK_MONOTONIC)`、Windows 用 `GetTickCount64()`。
- **Linux 续租兜底不再与系统 DHCPv6 客户端抢 UDP 546**：fork 续租命令前
  读 `/proc/net/udp6` 检测端口是否已被 dhcpcd/dhclient/systemd-networkd
  占用，已占用则只依赖 RS，不再启动竞争进程（避免
  `Address already in use`）。
- **续租子进程默认静音**：rdisc6/dhclient/dhcpcd 的输出重定向到
  `/dev/null`，不再污染客户端日志；设 `X3C_RENEW_DEBUG=1` 可放行排障。
- 认证后静默重连阈值放宽到 **180 秒**（握手阶段仍为 15 秒），认证后静默期
  不输出点号；抓包读错误（返回 -1，如网卡被拔出）改为打印错误后退出，
  交由外部守护重启，不再带坏句柄 goto 忙等。

### 工程
- Release CI：标签名带预发行后缀（含 `-`）时自动标记为 prerelease。

### 验证
- Windows 实网（I217-LM + Npcap）：认证秒级完成、Success 后无无谓重认证、
  心跳点号正常、IPv6 地址自动获取。
- Ubuntu 24.04 Live（TPACKET_V3，musl 全静态二进制）：poll 计时稳定，
  RS 后内核经 RA 安装全局地址与默认路由；NTP 回拨场景用时显示正常。
- 三平台 CI 构建全绿，glibc/musl/MinGW 三种工具链 `-Wall -Wextra` 零警告。

### 已知限制
- 180 秒静默判据仍是"无帧"启发式而非链路载波检测；物理拔线等场景最坏需
  180 秒恢复（载波事件即时重连计划在 1.2.0）。
- `-S` 只监听模式仍直接用 `pcap_next_ex`，仅排障用。
- H3C 私有保活（`19 2b 44 2b 32`，需 3DES + 双 MD5 挑战应答）仍未实现。

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

[1.1.2-rc.1]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.2-rc.1
[1.1.1]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.1
[1.1.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.0
[1.0.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.0.0
