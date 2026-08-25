# METHODOLOGY.md — 协议分析与调试思路

本文记录如何让一个跨平台 802.1X 客户端在真实的 H3C/iNode 校园网上跑通，
重点是**定位官方客户端与开源实现之间的差异**，而不是逐行翻译汇编。

## 一、整体思路

```
  (1) 找到协议参考实现 (njit8021xclient)
        │
        │  它已经实现了 EAPOL 状态机、H3C 双重 XOR+Base64 版本区、
        │  保活响应等核心逻辑
        ▼
  (2) 用抓包对比「能上网的官方客户端」与「我们的客户端」
        │
        │  逐字节对比 EAPOL 帧，找出差异点
        ▼
  (3) 针对差异点逐个修复
        │
        ▼
  (4) 跨平台适配 (Linux/macOS/Windows)
```

## 二、怎么认同源

二进制里能看到几个标志性常量，用它们在线搜索就能找到对应的开源项目：

- H3C 新旧密钥 `HuaWei3COM1X` / `Oly5D62FaE94W7`
- 内置版本串 `EN V3.60-6208`
- 状态机字符串 `[Authentication]`、`Success!`、`Send logoff!` 等

这些与 njit8021xclient 完全一致，说明协议核心同源。重写时**参照上游源码的
协议结构**，而不是从零逆向，工作量主要花在"恢复原厂的参数体系"和"对齐
真实网络行为"上。

## 三、定位关键差异（抓包对比法）

让一个能正常认证的官方客户端（如 Windows 上的 iNode）与我们的客户端分别
认证，用 Wireshark 或程序自带的 `-S`/`-d` 抓包，**逐字节对比 EAPOL 帧**。

真实网络上发现了四个与默认配置不同的关键点：

### 1. EAPOL-Start 要发往 H3C 私有多播地址

标准 802.1X 的 Start 帧发往 `01:80:c2:00:00:03`，但该网络的交换机只响应
发往 `01:d0:f8:00:00:03`（H3C 私有多播）的帧，且帧体需要补零到 64 字节。
发错地址会表现为：发出 Start 后**收不到任何 Request/Identity 回应**。

排障信号：`Sent a Start packet!` 之后长时间无下文。
解决：Start 与 Logoff 都改为发往 H3C 私有多播并补零。

### 2. 认证方法是 EAP type 0x07（明文密码），不是 MD5

服务器在 Request/Identity 之后发的挑战，EAP type 字节是 **`0x07`**，而不是
标准 EAP-MD5 的 `0x04`。type 0x07 的 Type-Data 结构是：

```
[1 字节: 密码长度][密码 ASCII][用户名]
```

即**密码以明文放在二层帧里**。原版状态机只处理 type 0x04（MD5 摘要），
收到 type 0x07 会打印 `Unknown EAP type: 0x07` 然后卡住。

排障信号：看到 `Unknown EAP type: 0x07`。
解决：新增 `send_response_plaintext()` 处理 type 0x07，载荷为
`[密码长度][密码][用户名]`。

### 3. 版本号不是 Web 上显示的那个

抓包里 Type-Data 里的 28 字符 Base64 版本区，解码后是一段乱码——因为它
经过两轮 XOR 加密，而且**内含时间戳随机数，每次都不同**，所以不能靠字符串
匹配去对齐。

需要逆运算把它解出来（见 `scripts/decode_version.py`）：

```
Base64 -> 20 字节
      -> 用 H3C 密钥 "Oly5D62FaE94W7" 逆 XOR
      -> 后 4 字节是大端 random
      -> random 转成 8 位十六进制字符串作为新密钥
      -> 再对前 16 字节逆 XOR
      -> 得到可读版本串，如 "CH\x11V7.xx-yyyy"
```

关键点：XOR 是"先正向再反向"，逆运算就是"先反向再正向"。用正确密钥解出
可读串；用错密钥得到乱码——这也能用来验证 `-x` 选 0 还是 1。

排障信号：认证失败报 `E255x`（版本不被接受）。
解决：`-V $'CH\x11V7.xx-yyyy'`，其中 `\x11` 是 V7 的分隔符。

### 4. Identity 响应不带 IP TLV

默认配置会在用户名后附加 `0x15` 类型的 IP TLV（把本机 IP 提交给服务器）。
该网络的成功报文里用户名后直接是版本区，没有 IP TLV，需要 `-i 0` 关闭。

## 四、排障工具

程序内置了几个不需要 Wireshark 的选项：

| 选项 | 用途 |
|---|---|
| `-l` | 列出所有网卡，确认 `-I` 该填什么 |
| `-S` | 只监听不认证，抓官方客户端的报文 |
| `-d` | 把收发的原始帧十六进制打印出来，逐字节对比 |
| `-L file` | 把日志写文件，方便事后分析 |

对比时重点看：目标 MAC、EAP type 字节、Type-Data 的长度与内容、版本区。

## 五、跨平台踩过的坑

### Windows

- 用户态发二层帧必须用 Npcap 内核驱动，没有纯用户态绕过方案。
- `-I` 接受网卡描述子串 / FriendlyName / 适配器 GUID / `\Device\NPF_{GUID}`，
  用 `-l` 先列出来再填。设备管理器里的"设备实例路径"不可用。
- 运行时需要管理员权限，且目标机器要装 Npcap（勾选 WinPcap 兼容模式）。

### 通用移植问题（已修复）

- Windows 没有 getopt_long，自带了一份兼容实现。
- 取 MAC/IP 在三个平台用不同 API：Linux ioctl、macOS getifaddrs、
  Windows GetAdaptersAddresses。
- 控制台需正确处理 UTF-8 与无缓冲输出。
- pcap 读超时设短（1s），否则 Ctrl-C 响应迟钝。

## 六、版本区反解脚本

`scripts/decode_version.py` 可独立使用，输入抓包里的 28 字符 Base64 版本区：

```sh
python3 scripts/decode_version.py '<Base64版本区>'
```

它会分别尝试新旧两个密钥并打印解密结果，同时显示尝试的 XOR 密钥，方便判断
该网络用的是哪套密钥（对应 `-x 0` 或 `-x 1`）。

## 七、状态与遗留

**已实网认证成功**：
- Windows x64 + Npcap
- macOS（getifaddrs / BPF）
- Linux（libpcap）协议代码与上述共用，但设备信息获取走独立的 ioctl 路径

遗留项：
- H3C 私有保活包（特征 `19 2b 44 2b 32`，需要 3DES + 双 MD5 挑战应答）
  在部分网络会出现；本项目遇到的网络未启用。若长时间运行后掉线，需要实现
  该响应（可参考 njit8021xclient 的 `HandleKeepOnline`）。
- `md5ver=1`（部分高校变体）仍是推测实现，抓包确认走 MD5 分支后才能验证。
- 认证成功后建议保持程序运行，服务器可能周期性重认证。
