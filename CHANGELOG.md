# Changelog

本项目版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.1-rc.3] - 2026-11-02

### 修复
- **修复 rc.2 在 Windows/Npcap 上实网认证基本不可用的回归**：rc.2 改用
  `pcap_getevent()` + `WaitForSingleObject()` 等待报文，但**没有同时设置
  `pcap_setmintocopy(h, 0)`**。Npcap 内核缓冲默认要攒满 16KB 才置位读事件，
  802.1X 这种几十字节的稀疏帧可能数分钟才被读到一次——实网表现为首个
  Request Identity 要约 3 分钟才出现，密码/MD5 挑战帧在 15s 握手窗口内
  永远等不到，反复 `Wait for handshake package timed out`。
  现 `pcap_open_live` 成功后立即在 Windows 上调用 `pcap_setmintocopy(h, 0)`
  （每帧到达即置位事件），恢复 rc.2 之前的即时收发。
- rc.2 的自管计时器（POSIX poll / Windows event）设计保留，仅补齐其
  Windows 前置条件。

## [1.1.1-rc.2] - 2026-11-01

> rc.1 标签因强移导致 GitHub Release 残留半残（0 附件、无法被 action 更新），
> 未正式发布即作废，改发 rc.2。rc.2 后又发现 Windows mintocopy 回归（见
> rc.3），**Windows 用户请直接使用 rc.3**。

### 修复
- **从根本上修复 macOS / 新 Linux 认证成功后反复全量重认证的问题**。原代码把
  "连续 15 次 `pcap_next_ex` 读超时无报文"当作掉线判据，但零流量时的 libpcap
  读超时是平台相关行为（本机实验确认）：
  - macOS BPF、Linux TPACKET_V2（旧版 libpcap）：到点返回 0；
  - **Linux TPACKET_V3（libpcap ≥ 1.5 的默认，覆盖当前主流发行版；本机
    libpcap 1.10.4 零流量实测阻塞超过 8 秒不返回）、Windows Npcap：首个报文
    到来前定时器不走，可能无限阻塞**。
  
  于是同一个"15 次超时"判据：在 macOS/旧 Linux 上每 ~15 秒误判掉线触发一次
  全量重认证（日志反复 `Wait for handshake package timed out...`）；在
  Windows/新 Linux 上则因阻塞"碰巧正常"，但真掉线时又**永远检测不到**。
- 新增跨平台可中断等待函数 `x3c_wait_frame()`（`reimpl/x3c.c`）：POSIX 侧
  用 `pcap_get_selectable_fd()` + `poll()`，Windows 侧用
  `pcap_getevent()` + `WaitForSingleObject()`，**自持 1 秒粒度计时，不再
  依赖平台相关的 libpcap 读超时**——静默看门狗与 `-6` IPv6 催促的秒表在
  三平台一致工作（`x3c_wait_frame` 取不到可等待句柄时才退回 `pcap_next_ex`，
  此时该平台的静默计时会失效，注释中已明确说明这一退化路径）。
- 认证成功后的静默重连阈值放宽到 **180 秒**（有线 802.1X 无客户端侧心跳要求，
  多数 H3C 网络 Success 后报文本就稀疏，不能据短暂无帧判掉线；交换机主动
  重认证会直接发 Identity 请求，照常应答不耽误）；**握手阶段仍为 15 秒**；
  认证后的静默期不再输出点号。
- 抓包句柄读错误（`pcap_next_ex` 返回 -1，如网卡被拔出/链路异常）此前被当成
  静默空转，会在不重建句柄的情况下 goto 回 Start 忙等重发 Start；现直接打印
  `pcap_geterr()` 错误后退出，交由外部（终端/procd 等）重启。
- 同样的等待与错误处理用于 Start 等待循环，Windows/Npcap 现在也会每秒重发
  一次 EAPOL-Start（此前零响应时只发一帧后无限阻塞）。

### 工程
- Release CI：标签名带预发行后缀（标签含 `-`，如 `v1.1.1-rc.2`）时自动将
  Release 标记为 prerelease（`.github/workflows/release.yml`）。

### 验证
- Linux（Ubuntu 24.04，TPACKET_V3）零流量 dummy 口实测：新代码稳定每秒
  1 个 tick、约每 12 秒一轮 Start 重试；旧代码在此环境下阻塞、计时完全不走动。
- 当前环境 `-Wall -Wextra` 编译零警告。

### 已知限制
- 180 秒静默判据仍是"无帧"启发式而非链路载波检测；极个别 Success 后永久静默
  且不允许重认证的网络可把该值调大（暂为硬编码，后续可做成命令行选项）。
- `-S` 只监听模式仍直接用 `pcap_next_ex`，在 BPF 平台零流量时可能忙等，
  仅排障用，暂不改动。

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

[1.1.1-rc.3]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.1-rc.3
[1.1.1-rc.2]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.1-rc.2
[1.1.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.1.0
[1.0.0]: https://github.com/thirtykmpersecond/x3c-inode/releases/tag/v1.0.0
