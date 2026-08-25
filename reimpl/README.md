# x3c8021x-re — H3C/iNode 802.1X 客户端（重写版）

基于对极路由固件 `/usr/sbin/x3c8021x` 二进制的逆向分析，在开源
[liuqun/njit8021xclient](https://github.com/liuqun/njit8021xclient) 协议核心
之上重写，**恢复了 HiWiFi 版命令行接口与全部可配置项**，并跨平台支持
Linux / macOS / Windows。

## 与二进制的对应关系（逆向确认）

| 二进制命令行 | 本程序 | 含义 |
|---|---|---|
| `-u` | username | 用户名 |
| `-p` | password | 密码 |
| `-I` | interface | 认证网卡（WAN，如 eth3） |
| `-x` | xorkey | 0=老版密钥 `HuaWei3COM1X`，1=新版密钥 `Oly5D62FaE94W7` |
| `-m` | mcast | 0=单播应答 1=多播应答（加入 `01:80:c2:00:00:03` 过滤） |
| `-i` | ipcommit | 0/1 提交网卡 IP 给服务器 |
| `-v` | vercommit | 0/1 提交版本号给服务器 |
| `-A` | assitif | 辅助接口（设置后从此口取IP，可空） |
| `-P` | privikey | 私钥，缺省 `1234567890123456`（=自动，用 xorkey 所选密钥） |
| `-M` | md5ver | 0=标准EAP-MD5，1=部分高校变体（需抓包确认） |
| `-V` | version | 上报版本串，如 `CH\x11V7.xx-yyyy` 或 `CH V3.60-6208` |

逆向确认的细节（均与源码对照）：
- 内置默认版本串 `EN V3.60-6208`（不是 njit 的 `CH V3.60-6208`）。
- Windows 版本区用 `r70393861` + XOR 填充（即 njit 注释掉的代码段）。
- 日志串与二进制完全一致：`[0] Client: Start.`、`[%d] Server: Request Identity!` 等。
- 标准 EAP-MD5 摘要 = MD5(id + 密码 + challenge)，不含 Value-Size 字节。

## 编译（跨平台）

**Linux**（需 libpcap 头文件）：
```sh
sudo apt-get install -y libpcap-dev build-essential
make
```

**macOS**（libpcap 系统自带）：
```sh
make
```
macOS 上 `-I` 用 `en0`/`en1` 等接口名；抓包需 root。

**Windows**（需 MinGW + Npcap）：
1. 安装 [Npcap](https://npcap.com)（勾选 Install in WinPcap API-compatible Mode）
2. 下载 [Npcap SDK](https://npcap.com/#download)，解压到任意目录
3. 交叉编译（在 Linux/macOS 上用 MinGW）：
```sh
make CC=x86_64-w64-mingw32-gcc NPCAP_DIR=/path/to/npcap-sdk OS=Windows_NT
```
   或在 Windows 上直接：
```sh
mingw32-make CC=gcc NPCAP_DIR=C:\path\npcap-sdk OS=Windows_NT
```
Windows 上 `-I` 支持以下写法（程序用 `pcap_findalldevs` 自动匹配）：
- 网卡描述子串（如 `Realtek` / `Intel` / `Ethernet`）
- 网卡友好名（`以太网` / `Ethernet`）
- 网络适配器 GUID（`{...}`）或 Npcap 设备名（`\Device\NPF_{GUID}`）

> 注意：设备管理器"详细信息"里的**设备实例路径**（`PCI\VEN_...`）不能用于抓包。

**OpenWrt 交叉编译**（MIPS mtmips）：
```sh
make CC=mips-openwrt-linux-uclibc-gcc
```

平台差异：
- MAC/IP 获取：Linux 用 ioctl(SIOCGIFHWADDR/SIOCGIFADDR)；macOS 用 getifaddrs；Windows 用 GetAdaptersAddresses。
- 参数解析：Windows 自带 getopt_long 实现（compat.c）；Linux/macOS 用系统版本。
- Linux/macOS 需 root 才能抓原始帧；Windows 需管理员权限与 Npcap。

## 运行

```sh
sudo ./x3c8021x-re -u <用户名> -p <密码> -I eth3 -x 1 -m 0 -i 0 -v 1 \
    -V 'CH\x11V7.xx-yyyy'
```

`-V` 中的 `\x11` 由程序内部解析为 0x11 字节（V7 版本串分隔符），可直接在命令行输入。

运行后出现 `Server: Success.` 即认证成功；`Server: Failure.` 会带
`E????:` 错误码（E2553密码错 / E2542账号已在线 / E2531用户不存在等）。
Ctrl-C 会发送 EAPOL-Logoff 再退出。

## 排障选项

| 选项 | 用途 |
|---|---|
| `-l` | 枚举抓包设备与系统适配器（含 MAC），先跑这个确定 `-I` 填什么 |
| `-L file` | 把输出写入日志文件 |
| `-d` | 十六进制转储收发的原始帧 |
| `-S` | 只监听不认证，抓 iNode 等客户端的报文做逐字节对比 |

**强烈建议**：如果默认参数不工作，用 `-S` 抓一份能正常认证的客户端（如 iNode）
的报文，再用 `-d` 对比自己发出的帧。详见上层目录 `METHODOLOGY.md`。

## 常见部署差异（重要）

不同高校的 H3C 网络配置可能不同，**不要假设默认参数普适**。已确认的差异点：

1. **认证方法**：标准是 EAP-MD5（type 0x04）；但部分部署改用
   **type 0x07 明文密码**（载荷 `[密码长度][密码][用户名]`）。本程序已实现
   `EAP_PLAINTEXT=7`。用抓包确认服务器请求的 type 字段即可分辨。
2. **EAPOL-Start 目标地址**：标准为 `01:80:c2:00:00:03`；部分 H3C 交换机
   只响应**私有多播 `01:d0:f8:00:00:03`**。本程序发往后者。
3. **版本串**：必须与服务器接受的值一致，且可能不是设备 WebUI 的默认值。
   用 `scripts/decode_version.py` 从抓包的 Base64 版本区反解（见上层目录）。
4. **Identity 是否带 IP 属性**：`-i` 控制；有的部署不带（`-i 0`）。

## 注意事项（尚未完全还原的部分）

1. **md5ver=1（部分高校变体）**：原二进制中未找到 AES-MD5 密钥与 privikey
   默认串，说明它**不是** bitdust fork 的 h3c-AES-MD5 算法。本程序对 md5ver=1
   按"密码先取 MD5 再参与摘要"实现（合理猜测），**未经实测**。
2. **privikey 语义**：二进制总是由 init 传 `1234567890123456`，且二进制内
   不含该串，是纯运行时参数。本程序实现为：显式设置非默认值则作为版本区
   XOR 密钥；默认值 = 自动（用 xorkey 所选密钥）。
3. **assitif**：按"取IP的辅助接口"实现；若为空则用 `-I` 网卡的 IP。
4. **H3C 心跳保活**：部分部署在认证后发特征 `19 2b 44 2b 32` 的私有包，
   要求 3DES+双MD5 挑战应答（参考原版 `HandleKeepOnline`）。本程序仅打印
   该类包不做响应；若长时间运行后掉线，需要补这段逻辑。

## 文件

| 文件 | 说明 |
|---|---|
| `x3c.c` | main + 参数解析 + 认证状态机 + 报文构建 |
| `dev.c` | 取 MAC/IP（Linux ioctl / macOS getifaddrs / Windows GetAdaptersAddresses） |
| `md5.c` | 自包含 MD5 + EAP-MD5 摘要（不依赖 openssl） |
| `compat.c/h` | Windows 兼容层（自带 getopt_long） |
| `x3c.h` | 配置结构与接口声明 |
| `Makefile` | Linux/macOS/Windows/OpenWrt 编译 |

## 安全提示

使用 type 0x07 明文密码的网络中，**密码以明文在二层传输**，任何能在该
广播域抓包的人都能读到。这是网络侧的协议设计，非客户端缺陷，建议不要
在其他系统复用此密码。

## 许可证

本程序派生于 [njit8021xclient](https://github.com/liuqun/njit8021xclient)
（GPLv2），按 **GNU GPL v2 或更高版本**分发，详见仓库根目录 `LICENSE`。

`md5.c` 的 MD5 实现基于 OpenSSL/RFC1321（Eric Young，BSD 风格许可）。
