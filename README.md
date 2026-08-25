# 极路由(HiWiFi) 离线ROOT + x3c8021x 插件分析

> 目标设备：极路由4增强版 / B70 (HC5962)，固件 1.4.8.20462s（2017-12-21）
> 分析日期：2026-08-18
> 前提：拥有路由器后台管理密码

---

## 0、项目结构

| 路径 | 内容 |
|---|---|
| `README.md` | 本文档（经验与结论，**第七章为认证成功的关键**） |
| `METHODOLOGY.md` | 完整逆向与调试思路（适合学习） |
| `bin/x3c8021x` | 路由器上拉取的原始 MIPS 二进制（27KB，入口 0x400b70） |
| `disasm/x3c8021x.dis` | capstone MIPS 反汇编（6608 条指令） |
| `disasm/disasm.py` | capstone 反汇编脚本 |
| `config/x3c8021x.config.example` | UCI 配置模板（凭据需自行填写） |
| `config/x3c8021x.init` | 启动脚本备份（含完整命令行拼装逻辑） |
| `scripts/hiwifi_offline_root.py` | 一键离线开 SSH（local_token→cloud_token） |
| `scripts/decode_version.py` | 反解 Base64 版本区（定位版本号的关键工具） |
| `scripts/cloud_token.py` / `cloud_token2.py` | 开 SSH 中间版本（保留供参考） |
| `scripts/main.go` | cloud_token 算法参考（imcdd/hiwifi-ssh-launcher） |
| `src/njit8021xclient/` | 同源开源项目源码（对照用） |
| `reimpl/` | ★★重写版 C 源码（恢复 HiWiFi 全部参数，跨平台） |

`reimpl/` 下不含预编译二进制，请 `make` 自行编译。详见 `reimpl/README.md`。

---

> ★★ **认证已实网成功（2026-08-18）**。关键结论见第七章：本校（目标高校）需
> ① EAPOL-Start 发往华三私有多播 `01:d0:f8:00:00:03`（**非**标准 `01:80:c2:00:00:03`）
> ② EAP **type 0x07 明文密码**（非 MD5-Challenge）
> ③ 版本号 **V7.xx-yyyy**（非极路由 WebUI 默认的 0548）
> ④ Identity 不带 IP 属性（`-i 0`）
> 四条全部靠 `-S` 抓 iNode 报文 + 反解 Base64 版本区定位，无一是猜出来的。

## 快速开始

### 1. 编译

```sh
cd reimpl
make            # Linux / macOS（Linux 需 libpcap-dev）
```

Windows 交叉编译（在 Linux 上，需 MinGW 与 Npcap SDK）：

```sh
make CC=x86_64-w64-mingw32-gcc NPCAP_DIR=/path/to/npcap-sdk OS=Windows_NT
```

Windows 上运行还需安装 [Npcap](https://npcap.com)（二层帧收发依赖其内核驱动，
任何语言都无法绕过）。详见 `reimpl/README.md`。

### 2. 查看网卡

```sh
sudo ./x3c8021x-re -l            # Linux/macOS
x3c8021x-re-win64.exe -l         # Windows（管理员权限）
```

### 3. 认证

```sh
sudo ./x3c8021x-re -u <用户名> -p <密码> -I <网卡> -x 1 -m 0 -i 0 -v 1 \
    -V 'CH\x11V7.xx-yyyy'
```

- `-I`：Linux 用 `eth0`/`enp3s0`，macOS 用 `en0`，Windows 可填网卡描述
  子串（如 `Realtek`/`Intel`），程序自动解析。
- `-V` 中的 `\x11` 由程序内部解析为 0x11 字节，可直接在命令行输入。
- 出现 `Server: Success.` 即成功；`Server: Failure.` 会带 `E????` 错误码
  （E2553 密码错 / E2542 已在线 / E2531 用户不存在）。
- Ctrl-C 会发送 EAPOL-Logoff 再退出。

> **不同高校参数可能不同。** 如果默认参数不工作，务必阅读下方第七章的定位方法：
> 用 `-S` 抓一份能正常认证的客户端（如 iNode）报文，再用 `-d` 逐字节对比。
> 完整思路见 [METHODOLOGY.md](METHODOLOGY.md)。

## 一、设备信息

| 项目 | 值 |
|---|---|
| 型号 | HC5962（极路由4增强版 B70） |
| 固件 | 1.4.8.20462s 171221-015119 |
| 架构 | MIPS mtmips_1004kc（MT7621） |
| 内核 | Linux 3.10.49 (OpenWrt/Linaro GCC 4.8-2014.04) |
| Web 服务 | QWS（极路由自家后端，非标准 LuCI） |
| 管理 IP | 192.168.199.1 |
| WAN 接口 | eth3（该设备实测为厦门大学校园网 DHCP） |
| 插件数据分区 | /tmp/cryptdata（mtdblock12, 35MB ubifs，加密分区） |

---

## 二、极路由离线获取 Shell（免拆机）★核心经验

极路由云平台已关停，无法走官方"开发者模式"。**离线 ROOT 原理**：路由器保留的 `/local-ssh/` 调试接口用 `cloud_token` 开启 22 端口，`cloud_token` 可由 `local_token` + `uuid` 本地计算（HMAC-SHA1，密钥=SHA1(uuid)），无需云端。

### 步骤

1. **获取 local_token**
   ```
   GET http://192.168.199.1/local-ssh/api?method=get
   # 返回 {"data":"RDRFRTA3NjE2QkM2LHNzaCwxNjA0Nzg4MDAwMDAwLF...","code":0}
   ```
   local_token = base64 解码后格式：`<MAC大写>,ssh,<时间戳>,<签名>`（时间戳每次刷新变化）

2. **获取 uuid**
   ```
   GET http://192.168.199.1/cgi-bin/turbo/proxy/router_info
   # data.uuid 字段，如 f692d022-9f8e-50f7-bfed-<路由器序列号/MAC>（固定）
   ```

3. **本地计算 cloud_token**（无需 hiwifi.wtf 在线服务，该站已关闭）
   ```
   msg  = base64_decode(local_token) 取前3段(逗号分隔)拼接，且时间戳+1
   即   "<MAC>,ssh,<ts+1>"
   key  = SHA1(uuid)
   cloud_token = base64( HMAC-SHA1(msg, key) )
   ```

4. **提交开启 22 端口**
   ```
   GET http://192.168.199.1/local-ssh/api?method=valid&data=<cloud_token URL编码，+转%2B>
   # 成功返回 {"data":"Success: ssh port is 22","code":0}
   ```

5. **连接 SSH**
   ```
   ssh root@192.168.199.1   # 密码 = 路由器后台管理密码
   # dropbear 只提供 ssh-rsa 主机密钥，OpenSSH 需加参数：
   ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.199.1
   ```

6. **永久开启 SSH**（临时权限约 5 分钟失效）
   ```
   /etc/init.d/dropbear enable && /etc/init.d/dropbear start
   ```

### 可复用脚本（Python + paramiko）

见同目录 `hiwifi_offline_root.py`，一键完成 3/4 步（计算并提交 token）。

---

## 三、x3c 插件分析（华三认证）

### 3.1 是什么

"华三认证" 入口在 Web 后台「互联网」菜单下，`/admin_web/plugin/hua_san`。其底层软件包为 **`x3c8021x`**，是极路由官方固件内置的 H3C iNode 802.1x 认证客户端。

| 项目 | 值 |
|---|---|
| 包名 | x3c8021x |
| 版本 | 1.3-20140715 |
| 描述 | "802.1X client compatable with H3C iNode 802.1X client. Support H3C/iNode's private authentication protocol v2.4-v5.1" |
| 依赖 | libc, libpcap (libpcap.so.1.3) |
| 架构 | mtmips_1004kc |
| 二进制 | /usr/sbin/x3c8021x (27KB, ELF32 MIPS, mips32r2, 动态链接 uClibc) |
| 启动 | /etc/rc.d/S54x3c8021x |

### 3.2 相关文件

```
/etc/config/x3c8021x                          # UCI 配置
/etc/init.d/x3c8021x                          # 启动/停止脚本
/etc/hotplug.d/gmac/wan/50-x3c8021x           # WAN 插拔自动重连
/etc/logrotate.d/x3c8021x                     # 日志轮转
/usr/sbin/x3c8021x                            # 主程序
/usr/lib/lua/luci/view/admin_web/plugin/hua_san.htm  # Web 配置页
/usr/lib/opkg/info/x3c8021x.{control,list}    # 包信息
/tmp/log/x3c8021x.log                         # 运行日志
```

### 3.3 配置项（/etc/config/x3c8021x）

```
config base_set
    option wanif 'eth3'      # 认证网卡
    option enable '1'
    option username '账号'
    option password '密码'

config adv_set
    option xorkey '1'        # XOR密钥 0=老版 1=新版
    option mcast '0'         # 组播 0/1
    option ipcommit '1'      # IP提交
    option vercommit '1'     # 版本提交
    option assitif 'br-lan'  # 辅助接口
    option lang 'CH'         # 语言
    option privikey 'nil'    # 私有密钥（nil→默认1234567890123456）
    option ver 'V7.30-0548'  # 模拟的 iNode 客户端版本号
    option md5ver '0'        # MD5版本 0=标准 1=部分高校
```

### 3.4 命令行参数

```
/usr/sbin/x3c8021x -u <用户> -p <密码> -I <网卡> -x <xorkey> -m <mcast>
    -i <ipcommit> -v <vercommit> -A <assitif> -P <privikey> -M <md5ver> -V <版本>
```

版本号编码逻辑（init.d 脚本中）：
- 版本号第2位数字 > 3（如 V7.30）：`Fullver = "CH\x11" + "V7.30-0548"`（\x11 分隔符，iNode V7 格式）
- 否则：`Fullver = "CH V3.60-6208"`（V3 老格式）

### 3.5 认证流程（日志还原）

```
[*] Client: Start.
[1] Server: Request Identity!       # 服务器请求身份
[1] Client: Response Identity.
[2] Server: Request Allocated!      # H3C 私有 EAP 类型 (type 7 / AVAILABLE)
[2] Client: Response Allocated.
[2] Server: (H3C private data)      # H3C 私有数据帧
[2] Server: Success.                # 认证成功
```

实测日志中认证成功；早期有一次 `E63034: LDAP用户不存在或密码错误` 失败记录（账号/密码错误，后已修正成功）。

---

## 四、反编译分析

### 4.1 工具链

- 拉取二进制：SSH exec `cat` 直接读字节（路由器无 base64/sftp）
- 反汇编：`capstone` (CS_ARCH_MIPS | CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)，无 section header 需从 entry 0x400b70 / 代码段 0x400134-0x406874 起反汇编，共 6608 条指令
- 函数识别：`radare2`（`r2 -A`；entry0 / main@0x400d10 / x3c_auth 主状态机 fcn.00401070，3252字节）
- 完整反编译到 C 需要 Ghidra（本环境未安装）；已通过字符串+常量确认源码同源

### 4.2 关键字符串（含调试符号残留）

```
x3c.c, dev.c, md5.c           # 源码文件名
x3c_auth                      # 认证函数名
eap_fill_md5                  # MD5 填充函数
dev_get_mac / dev_get_ip
(ether proto 0x888e) and (ether dst host ...)   # EAPOL BPF 过滤器
%s: need root privilege!!!
[%d] Server: Request Allocated! / Response Allocated.
[%d] Server: Request MD5-Challenge! / Response MD5-Challenge.
[%d] Server: (H3C private data)
```

### 4.3 ★同源确认：x3c8021x 就是 njit8021xclient

二进制中的三个 H3C 私有协议常量与开源项目 **liuqun/njit8021xclient** 完全一致：

| 二进制字符串 | njit8021xclient 源码 | 含义 |
|---|---|---|
| `Oly5D62FaE94W7` | auth.c:40 `H3C_KEY` | H3C 固定密钥 |
| `HuaWei3COM1X` | auth.c:41 `H3C_KEY2` | H3C 固定密钥2 |
| `r70393861` | auth.c:581 `WinVersion` | Windows 版本号串 |
| `EN V3.60-6208` | auth.c `H3C_VERSION` | 客户端版本格式 |

**结论**：极路由官方基于开源 njit8021xclient 二次开发，编译打包成闭源 MIPS 二进制 `x3c8021x`，改名为"华三认证"插件。

> ⚠️ **注意：程序本体 ≠ 原版开源代码**。协议加密核心（H3C_KEY/H3C_KEY2、EAP 状态机、版本区 XOR 填充）完全一致，但**命令行接口是极路由工程师重写的**，并新增了大量可配置项：
>
> | | liuqun/njit8021xclient 原版 | x3c8021x 二进制 |
> |---|---|---|
> | 参数解析 | 仅 `njit-client 用户 密码 [网卡]` | getopt_long：`-u -p -I -x -m -i -v -A -P -M -V` |
> | 密钥切换 xorkey | 无（固定用 H3C_KEY） | 有，0=旧 1=新 |
> | 组播/提交IP/提交版本 | 固定 | mcast/ipcommit/vercommit 可开关 |
> | 私有密钥 privikey | 无 | 有（默认 1234567890123456） |
> | 版本上报 | 固定 `CH V3.60-6208`（V3 格式） | 支持 iNode V7：`CH\x11V7.30-0548` |
> | 学校变体 | 无 | md5ver（部分高校变体） |
>
> 这些正是不同学校 H3C 服务器差异化的兼容开关，原版没有。

### 4.4 反编译状态与"重新编译"可行性

- 目前产物是 **MIPS 汇编**（`x3c8021x.dis`）+ radare2 函数边界（main@0x400d10、认证状态机 fcn.00401070），**尚未做 C 级反编译**（需要 Ghidra）。
- MIPS 汇编无法直接"重新编译"回二进制（PLT 重定位、$gp 相对寻址等问题）。
- 要得到可重新编译的代码，工程上正解是：**以 njit8021xclient 为骨架，补上上表的 getopt 接口与 xorkey/V7/md5ver 等功能**，再用对应平台交叉编译（MIPS 用 OpenWrt SDK / buildroot）。
- 但**该二进制本身已经能在本网络认证成功**，若只是换一台 MIPS 路由器直接拷二进制即可；换 x86/ARM 平台才需要重新编译源码。

### 4.5 等价开源替代方案（可自行编译到 OpenWrt/路由器）

| 项目 | 地址 | 特点 |
|---|---|---|
| liuqun/njit8021xclient | github.com/liuqun/njit8021xclient | 最原始、与 x3c 同源 |
| KiritoA/c3h_client | github.com/KiritoA/c3h_client | 含 openwrt 交叉编译 makefile，断线重连 |
| QCute/H3C | github.com/QCute/H3C | 纯 raw socket + 本地 MD5，无 libpcap 依赖 |
| wogong/nu-h3c | github.com/wogong/nu-h3c | 单文件 5K 最轻量，带 LuCI 配置 |

---

## 五、Web API 备忘（后续操作有用）

登录：`GET /cgi-bin/turbo/api/login/login_admin?username=admin&password=<明文>` → `stok` + `Set-Cookie: sysauth`
注意 stok 格式为 `/;stok=xxx`，正确路径为 `/cgi-bin/turbo/;stok=xxx/...`（少个斜杠会 404/重定向）。

| 接口 | 用途 |
|---|---|
| `POST /cgi-bin/turbo/;stok=xxx/proxy/call` body=`{"method":"...","data":{},"lang":"zh-CN","version":"v1"}` | 通用 OpenAPI 调用 |
| `method=service.pluginm.list` | 插件列表（web 会话返回空；插件管理需 App 权限） |
| `method=wan.get_status` | WAN 状态 |
| `GET /cgi-bin/turbo/;stok=xxx/api/plugin/get_x3c` | 读 x3c 配置（含明文密码） |
| `GET /cgi-bin/turbo/;stok=xxx/api/plugin/set_x3c` | 保存 x3c 配置 |
| `GET /cgi-bin/turbo/;stok=xxx/admin_web/plugin/logs?type=x3c` | x3c 运行日志页 |
| `GET /cgi-bin/turbo/;stok=xxx/admin_web/plugin/hua_san` | 华三认证配置页 |
| `system.diagnose.start` + `get_result` | 生成诊断报告（加密，熵8.0无法直接读） |

---

## 六、注意事项 / 安全提醒

1. 临时 SSH 约 5 分钟失效；做永久开启前先执行 `dropbear enable`
2. 极路由云停服后：原插件/App 均不可用，刷第三方固件（Padavan/OpenWrt）前**务必备份** mtd 分区（尤其 EEPROM 无线校准数据）
3. x3c 配置中密码为明文存储在 `/etc/config/x3c8021x`，且 `get_x3c` 接口返回明文密码，注意网络访问控制
4. 本机当前用户 `bio` 有 sudo；脚本依赖 paramiko（Python）
---

## 七、Windows 移植与实网抓包定位（2026-08-18 续）

在 Windows 上跑通重写版时踩了一串坑，最终靠抓 iNode 报文定位到**协议层的真实差异**。

### 7.1 ★四项关键差异（全部实网验证通过）

与开源原版 / 极路由默认配置的差异汇总：

| # | 项目 | 原版/默认 | 本校实际 | 后果 |
|---|---|---|---|---|
| 1 | EAPOL-Start 目标 | `ff:ff:ff:ff:ff:ff` + `01:80:c2:00:00:03` | **`01:d0:f8:00:00:03`** | 交换机不受理，永不建立会话 |
| 2 | 第二阶段 EAP type | `0x04` MD5-Challenge | **`0x07` 明文密码** | 走 `default:` 分支直接退出 |
| 3 | 上报版本号 | `V7.30-0548`（WebUI默认） | **`V7.xx-yyyy`** | 版本区校验失败被静默丢弃 |
| 4 | Identity 的 IP 属性 | 带 `0x15` | **不带**（`-i 0`） | 结构不符被丢弃 |
| 5 | Start 帧长 | 18 字节 | **64 字节**（补零） | 可能被丢 |

目标高校（交换机 `<交换机MAC>`）的实际认证序列，来自 iNode 客户端抓包：

| 阶段 | 交换机请求 | iNode 响应 |
|---|---|---|
| 1 | `01 01 00 05 01`（type=1 Identity） | `02 01 00 2f 01` + `06 07` + 28B Base64版本区 + 两空格 + 用户名 |
| 2 | `01 02 00 05 **07**`（type=**7**） | `02 02 00 1a **07** <passlen> <密码> <学号>` |
| 3 | `0a 02 ... 19 3f ...`（H3C 私有数据） | — |
| 4 | `03 02 00 04`（EAP Success） | — |

原重写版只实现 type 1/2/4/0x14，遇到 **0x07 走 `default:` 分支直接 `return -1` 退出** —— 表现为"响应了 Identity 就没下文"。

**误判修正记录**（避免后人重走）：
- ❌ 曾怀疑 `0x06 0x07` 版本区长度字节写错 → 查原版 `auth.c:378` 确认这是**固定魔术字节非长度字段**，实现正确
- ❌ 曾怀疑漏了 `0x16 0x20` 心跳挑战（原版 `have1620CODE` 分支）→ 抓包证明服务器 Identity 请求是最精简的 5 字节，无附加属性
- ❌ 曾怀疑以太帧不足 60 字节被丢 → 原版同样不补齐，排除
- ❌ 曾误判"EAP id 卡在 1 说明包被丢"→ 实际 id 递增 8→14→15→17，是交换机周期性重发；id=1 那些是发往 `01:80:c2:00:00:03` 的组播探询
- ❌ 曾误判工具输出被篡改而中止排查 → 是把 `set -x` 的 stderr/stdout 管道缓冲错序当成证据，判断有误

### 7.2 抓包确认的正确参数（本校）

```
x3c8021x-re-win64.exe -u <学号> -p <密码> -I <网卡名> \
    -x 1 -m 0 -i 0 -v 1 -V "CH\x11V7.xx-yyyy"
```

- `-i 0` **必须**：iNode 的 Identity 里**没有** `0x15` IP 属性（认证发生在取 IP 之前）
- `-V "CH\x11V7.xx-yyyy"` **必须**：yyyy 是反解 iNode 版本区得到的，WebUI 默认 0548 会失败
- `-v 1` 保留：iNode 确实发送 `06 07` + 28 字节 Base64 版本区
- 用户名 `<学号>` **不带任何域后缀**
- `-M` 已无意义：该网络根本不走 MD5 分支，故先前标注"未验证"的 md5ver=1（部分高校变体）对本校用不上
- 路由器 `/etc/config/x3c8021x` 里的账号是 `<示例账号>`（前任用户），其"这套参数可用"从未被验证

### 7.3 新增代码（reimpl/x3c.c）

```c
typedef enum { EAP_IDENTITY=1, EAP_NOTIFICATION=2, EAP_MD5=4,
               EAP_PLAINTEXT=7, EAP_AVAILABLE=20 } eap_type_t;
```

`send_response_plaintext()`：载荷 `[密码长度1字节][密码][用户名]`，EAP 长度 = `i-18`。
已用独立测试程序逐字节比对，与 iNode 抓包**完全一致**：

```
01 00 00 1a 02 02 00 1a 07 0a 46 61 66 75 39 30 31 31 39 39 41 45 32 35 30 39 30 30 30 38
```

### 7.3b ★Base64 版本区反解方法（定位版本号的关键手段）

版本区含时间戳随机数，**每次运行 Base64 都不同，不能直接比对字符串，必须反解**：

1. Base64 解出 20 字节
2. 用 H3C 密钥（`Oly5D62FaE94W7`）做逆 XOR → 得 clientarea
3. 后 4 字节按大端读出 random
4. `"%08x" % random` 作为密钥，逆 XOR 前 16 字节 → 得版本串

`XOR` 是「先正向异或、再反向异或」，逆运算为「先反向、再正向」。
脚本见 `scripts/decode_version.py`。用老版密钥 `HuaWei3COM1X` 解出乱码可反证 `-x 1` 正确。

实测结果（反解后）：
```
iNode 版本区 <Base64版本区>
  -> 43 48 11 56 ... （'CH' + 0x11 + 可读版本串 + 尾部补零）
  -> 'CH\x11V7.xx-yyyy'
```

### 7.4 Windows 移植修复的 Bug（按发现顺序）

| # | Bug | 症状 | 修复 |
|---|---|---|---|
| 1 | 自写 `getopt_long` 对纯标志短选项返回 0（POSIX 中 0 表示选项结束） | `-l` 被当成非法参数打印 usage | 逐字符返回选项字符，正确推进 `optind`/`optpos` |
| 2 | ★`x3c_get_mac`/`x3c_get_ip` **漏调第二次 `GetAdaptersAddresses`** | 遍历未初始化堆内存 → `0xC0000005` 访问违规；堆恰为 0 时静默退出无任何输出 | 补填充调用 + 失败时 `free` 并报错 |
| 3 | `find_adapter` 只精确匹配 FriendlyName/AdapterName | `-I <网卡名>` 取 MAC 失败（该网卡 FriendlyName 为空） | 传入解析后的 NPF 名，增加 `strstr(dev, AdapterName)` 子串匹配 |
| 4 | `strncmp(a->AdapterName, ...)` 未判 NULL | 潜在崩溃 | 补 NULL 检查 |
| 5 | UTF-8 源码字符串在 GBK 控制台显示 | 中文全乱码 | `SetConsoleOutputCP/SetConsoleCP(CP_UTF8)` |
| 6 | stdout 经 sudo 管道时全缓冲 | 程序阻塞在认证循环，输出一行不见 | `setvbuf(stdout, NULL, _IONBF, 0)` |
| 7 | `pcap_compile/setfilter` 返回值未检查 | 失败后用未初始化 `fcode` | 检查返回值并打印 `pcap_geterr` |
| 8 | 命令行无法输入 0x11 分隔符 | V7 版本串没法表达 | `-V` 支持 `\xNN` 转义（`unescape()`） |
| 9 | ★`pcap_open_live` 读超时设成 60000ms | 每次收包最长阻塞 60 秒，"要跑很久才有响应" | 改 1000ms |
| 10 | ★`DPRINTF` 走 stderr、`hexdump` 走 stdout | 两流独立缓冲 → 日志错序、末尾内容滞留丢失，**曾误判"服务器无响应"** | 统一 `DPRINTF` 走 stdout |
| 11 | 握手循环 `start_count` 收包后不重置 | 累加到 3 就误判超时跳回重来 | 改局部 `idle`，收包归零，窗口 15s |
| 12 | ★EAPOL-Start 发往标准多播 | 交换机不受理，永不建立会话 | 改发 `01:d0:f8:00:00:03`，补零 64 字节 |

### 7.5 新增排障选项

| 选项 | 用途 |
|---|---|
| `-l` / `--list` | 枚举 Npcap 设备 + 系统适配器（含 MAC）对照表 |
| `-L file` / `--log` | 输出重定向到文件（绕开控制台/提权窗口问题） |
| `-d` / `--dump` | 十六进制转储收发的原始帧 |
| `-S` / `--sniff` | ★只监听不认证，抓 iNode 等客户端报文做逐字节对比 |

`-S` 是本次定位成功的关键：直接抓到能用的客户端发什么，比盲试参数组合可靠得多。

### 7.6 Windows 运行须知

- **必须装 Npcap**：Windows 用户态无法收发二层帧，802.1X 必须靠 Npcap 内核驱动。静态链接只能免掉 `wpcap.dll` 依赖，**驱动省不掉**
- **必须管理员权限**
- `-I` 可填：网卡描述子串（如 `Realtek`）、FriendlyName、适配器 GUID、或完整 `\Device\NPF_{GUID}`；程序用 `pcap_findalldevs` 自动解析
- **设备管理器里的"设备实例路径"（`PCI\VEN_...`）不能用**，与 Npcap 的 `NPF_{GUID}` 是两套东西
- 交叉编译：`make CC=x86_64-w64-mingw32-gcc NPCAP_DIR=/path/to/npcap-sdk OS=Windows_NT`
- 不要用 Windows 11 的 `sudo`（提权进程控制台可能分流），直接用管理员 CMD

### 7.7 安全提醒（重要）

**该校园网密码以明文过网。** 抓包中 type 0x07 响应里密码字段是可直接读出的 ASCII（`07 <passlen> <明文密码> ...`）。这是网络侧的协议设计，非客户端缺陷，**建议不要在其他场合复用该密码。**

### 7.8 状态与遗留

**✅ 已实网认证成功**（2026-08-18，目标高校）：
- Windows x64 + Npcap —— 已验证
- macOS（getifaddrs / BPF）—— 已验证
- Linux（AF_PACKET via libpcap）—— 未实测，协议代码与上述共用

遗留项：
- 阶段 3 的 H3C 私有保活包（`19 3f 36 06 ...`，含 `43 11 <会话ID>` 等 TLV）
  目前仅打印特征字节未做响应。若长时间运行后掉线，需实现该保活响应（参考原版 `HandleKeepOnline`）
- `md5ver=1`（部分高校变体）仍是**推测实现、未验证**；本校不走 MD5 分支故用不上
- Linux 分支未实网验证（`dev.c` 走 ioctl `SIOCGIFHWADDR`/`SIOCGIFADDR`，与已验证的两平台是独立代码路径）
- 认证成功后建议保持程序运行；服务器可能周期性重认证
