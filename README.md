# x3c8021x-re — 跨平台 H3C/iNode 802.1X 客户端

C 语言实现的 H3C/iNode 校园网 802.1X 认证客户端，支持 **Linux / macOS / Windows**。
基于开源 [njit8021xclient](https://github.com/liuqun/njit8021xclient) 的协议核心，
恢复了原厂固件版的全部命令行参数与厂商私有扩展（版本区双重 XOR+Base64、
EAP type 0x07 明文密码、私有多播地址等）。

已在 Windows（Npcap）与 macOS（BPF）实网认证成功。

## 特性

- 标准 EAP-MD5（type 0x04）与 H3C 私有 **EAP type 0x07 明文密码**两种认证方法
- H3C 私有版本区：16 字节版本串 + 随机数，两轮 XOR 后 Base64 编码
- **认证成功后自动催促 IPv6 配置**（`-6`，缺省开启）：检测到网卡只有
  链路本地地址时发 ICMPv6 RS，必要时调用系统 DHCPv6 续租，解决认证放行
  前 RS 被丢弃导致长时间拿不到 IPv6 的问题
- 跨平台二层帧收发（Linux libpcap / macOS BPF / Windows Npcap）
- 保活心跳日志精简：Success 后的周期性 Identity 轮询只输出点号，每 30 次
  打一行汇总，长时间运行日志不再被刷屏
- 丰富的排障选项：枚举网卡、十六进制转储、只监听抓包对比
- V7 版本串分隔符 `0x11` 的命令行 `\xNN` 转义
- Ctrl-C 自动发送 EAPOL-Logoff

## 快速开始

### 编译

**Linux**（需 libpcap）：
```sh
sudo apt install libpcap-dev build-essential
cd reimpl && make
```

**macOS**（libpcap 系统自带）：
```sh
cd reimpl && make
```

**Windows**（交叉编译，在 Linux 上；或在 Windows 上用 MinGW）：
```sh
# 1. 安装 MinGW：sudo apt install gcc-mingw-w64-x86-64
# 2. 下载 Npcap SDK 到某目录：https://npcap.com/#download
cd reimpl
make CC=x86_64-w64-mingw32-gcc NPCAP_DIR=/path/to/npcap-sdk OS=Windows_NT
```
目标机器还需安装 [Npcap](https://npcap.com)（勾选 WinPcap API-compatible Mode）。
Windows 用户态收发二层帧必须依赖其内核驱动，无法绕过。

### 查看网卡

```sh
sudo ./x3c8021x-re -l            # Linux/macOS
x3c8021x-re-win64.exe -l         # Windows（管理员权限）
```

### 认证

```sh
sudo ./x3c8021x-re -u <用户名> -p <密码> -I <网卡> [选项]
```

出现 `Server: Success.` 即认证成功；`Server: Failure.` 会带 `E????` 错误码
（E2553 密码错 / E2542 已在线 / E2531 用户不存在等）。

> **不同高校的参数可能不同**，不要假设默认值普适。如果认证不通过，
> 请阅读下文「适配不同网络」与 [METHODOLOGY.md](METHODOLOGY.md)，
> 用 `-S` 抓一份能用的客户端（如 iNode）报文来定位差异。

## 命令行参数

| 参数 | 含义 |
|---|---|
| `-u` | 用户名 |
| `-p` | 密码 |
| `-I` | 认证网卡（Linux `eth0`/macOS `en0`/Windows 网卡描述子串） |
| `-x` | xorkey：0=老版密钥 `HuaWei3COM1X`，1=新版 `Oly5D62FaE94W7` |
| `-m` | mcast：0=单播应答，1=多播应答（加入 `01:80:c2:00:00:03` 过滤） |
| `-i` | ipcommit：0/1 是否把 IP 放进 Identity 响应 |
| `-v` | vercommit：0/1 是否上报版本号 |
| `-A` | 辅助接口（从该口取 IP，可空） |
| `-P` | 私钥（缺省 `1234567890123456` = 自动用 xorkey 所选密钥） |
| `-M` | md5ver：0=标准 EAP-MD5，1=部分高校变体（需抓包确认） |
| `-6` | v6kick：**0/1 认证成功后主动催促 IPv6（发 RS，必要时系统续租），缺省 1** |
| `-V` | 上报版本串，如 `CH\x11V7.xx-yyyy`（`\x11` 由程序解析） |
| `-l` | 枚举抓包设备与系统适配器 |
| `-L file` | 输出写入日志文件 |
| `-d` | 十六进制转储收发的原始帧 |
| `-S` | **只监听不认证**，抓 iNode 等客户端的报文做对比 |
| `-h` | 帮助 |

## 适配不同网络

H3C 校园网在不同高校的部署存在差异，常见不同点：

| 差异点 | 可能取值 | 如何确定 |
|---|---|---|
| 认证方法 | type 0x04 MD5 或 **type 0x07 明文密码** | 抓包看服务器请求的 type 字节 |
| EAPOL-Start 目标 MAC | 标准 `01:80:c2:00:00:03` 或 H3C 私有 `01:d0:f8:00:00:03` | 抓包看正常客户端第一个帧 |
| 版本串 | `CH\x11V7.xx-yyyy` 或 `CH V3.60-6208` 等 | 反解 Base64 版本区（见下） |
| Identity 是否带 IP | `-i 0` 或 `-i 1` | 对比成功报文的 Type-Data |

**定位方法：用 `-S` 抓包 + `-d` 对比 + `scripts/decode_version.py` 反解版本号。**
完整思路与踩坑记录见 [METHODOLOGY.md](METHODOLOGY.md)。

### 反解版本串

版本区是含随机数的 Base64，每次都不同，不能直接比对字符串，要逆运算：

```sh
python3 scripts/decode_version.py '<抓包里的28字符Base64版本区>'
```

用正确的 H3C 密钥会解出形如 `CH\x11V7.xx-yyyy` 的可读串；用错密钥则是乱码
（这也能反过来验证 `-x` 取值）。

## IPv6 支持

抓包证实（H3C 校园网，iNode 拨号信息显示 IPv6=DHCPv6）：**iNode 从不在
802.1X/EAPOL 报文中携带任何 IP 地址**，IPv6 绑定由交换机监听 DHCPv6 交互
自动生成。因此客户端不需要、也不应该在认证报文中上送 IPv6 地址。

实际问题是：认证放行前主机发出的 ICMPv6 路由器请求（RS）会被未认证端口
丢弃，而网卡一直 up 时系统重试间隔很长，导致认证成功后长时间只有 `fe80`
链路本地地址。`-6`（缺省开启）在收到 EAP Success 后执行非阻塞流程，
不影响保活应答：

1. 检测网卡是否已有非链路本地地址——全局单播 `2000::/3` 与 ULA
   （`fc00::/7`）都算"已配置"，只有 `fe80::/10`（或无地址）才继续；
2. 第 1/6/14 秒各注入一帧 ICMPv6 Router Solicitation（源地址取系统真实
   链路本地地址，取不到时按 RFC 4861 用 `::` 且不带 SLLA 选项），网关
   回 RA 后由**内核自己**完成 SLAAC/DHCPv6；
3. 仍无地址则后台执行一次系统原生命令兜底（Windows `ipconfig /renew6`，
   Linux 依次尝试 `rdisc6`/`dhclient -6`/`dhcpcd -6`，
   macOS `ipconfig set <if> AUTOMATIC-V6`）；
4. 40 秒仍无则放弃并提示该网络可能未部署 IPv6。

不在用户态伪造 DHCPv6——租约由内核协议栈维护，伪造报文内核不会安装
地址/DNS/路由。排障可设环境变量 `X3C_DUMPV6=1` 转储发出的 RS 原始帧，
不需要此功能加 `-6 0`。实现细节见 [reimpl/README.md](reimpl/README.md)。

## 日志

认证握手阶段逐帧详细打印（加 `-d` 带十六进制转储）；Success 之后的周期性
Identity 保活轮询只输出点号，每 30 次打一行 `[hb] 已应答 N 次保活`，
Failure、私有数据、重新认证挑战等非心跳报文仍完整打印。

## 项目结构

| 路径 | 说明 |
|---|---|
| `reimpl/` | ★ C 源码与 Makefile（核心） |
| `reimpl/x3c.c` | main + 参数解析 + EAP 状态机 + 报文构建 |
| `reimpl/ipv6.c/h` | 认证成功后的 IPv6 自动配置催促（检测→RS→系统续租） |
| `reimpl/dev.c` | 取 MAC/IP（Linux ioctl / macOS getifaddrs / Windows GetAdaptersAddresses） |
| `reimpl/md5.c` | 自包含 MD5（不依赖 OpenSSL） |
| `reimpl/compat.c/h` | Windows 兼容层（自带 getopt_long） |
| `scripts/decode_version.py` | 反解 H3C Base64 版本区 |
| `METHODOLOGY.md` | 协议分析与调试方法论 |
| `LICENSE` | GPLv2 |

## 安全提示

使用 EAP type 0x07 的网络中，**密码以明文在二层传输**，同一广播域内抓包即可
读到。这是网络侧的协议设计，非客户端缺陷，建议不要在其他系统复用同一密码。

本项目仅用于连接你有权使用的网络并学习网络协议，请遵守当地法律。

## 许可证

派生于 [njit8021xclient](https://github.com/liuqun/njit8021xclient)（GPLv2），
按 **GNU GPL v2 或更高版本**分发，详见 [LICENSE](LICENSE)。
`md5.c` 基于 OpenSSL/RFC1321（Eric Young，BSD 风格许可）。
