/* ipv6.c - 认证成功后主动催促 IPv6 自动配置 (RS + 系统 DHCPv6 回退)
 *
 * 流程(非阻塞, 由主循环 1s 粒度驱动):
 *   收到 Success
 *     -> 立即检测网卡是否已配置非链路本地地址(2000::/3 或 ULA fc00::/7 等)
 *     -> 只有 fe80::/10(或无地址)则在第 1/6/14 秒各发一帧 ICMPv6 RS
 *        网关回 RA 后内核自己完成 SLAAC/DHCPv6
 *     -> 第 10/20 秒仍只有链路本地地址, 后台调用系统原生命令续租一次:
 *          Windows: ipconfig /renew6
 *          Linux:   rdisc6 / dhclient -6 / dhcpcd(按可用性)
 *          macOS:   ipconfig set <iface> AUTOMATIC-V6
 *     -> 第 50 秒仍无则放弃(该网络可能未部署 IPv6)
 *
 * 本程序是自由软件, 按 GPLv2+ 许可分发(派生于 njit8021xclient)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <pcap.h>
#include "ipv6.h"

/* 时间参数(秒) */
#define V6_RS_DELAYS     {1, 6, 14}
#ifdef _WIN32
/* 实测 Windows 收到 M=1 的 RA 也不会重启已 release 的 DHCPv6 IA,
 * 必须 ipconfig /renew6, 故尽早回退 */
#define V6_RENEW_AT      10
#else
#define V6_RENEW_AT      20
#endif
#define V6_GIVEUP_AT     40
#define V6_RS_COUNT      3

enum { KS_OFF = 0, KS_ACTIVE, KS_OK, KS_FAIL };

/* ---------- 地址分类 ----------
 * 判据: 只有链路本地(fe80::/10)/环回/未指定才算"尚未配置", 需要催促;
 * 其余单播地址一律视为已配置 —— 既包括全局单播 2000::/3,
 * 也包括 ULA(fc00::/7, 部分校园/企业用 DHCPv6 下发) 等。
 * (组播 ff00::/8 不会出现在单播地址列表里, 无需单独排除) */

static int is_unspecified_or_loopback_v6(const uint8_t *b)
{
	int i;
	for (i = 0; i < 15; i++)
		if (b[i] != 0)
			return 0;
	return b[15] == 0 || b[15] == 1;   /* :: 或 ::1 */
}

static int is_linklocal_v6(const uint8_t *b)
{
	return b[0] == 0xfe && (b[1] & 0xc0) == 0x80;
}

/* 可作为"IPv6 已配置"依据的地址: 非链路本地/非环回/非未指定 */
static int is_configured_v6(const uint8_t *b)
{
	return !is_linklocal_v6(b) && !is_unspecified_or_loopback_v6(b);
}

/* 取指定网卡的链路本地地址(Windows 默认用 RFC7217 稳定地址而非 EUI-64,
 * 不能由 MAC 推算, 必须查系统) */

#ifdef _WIN32
static int adapter_match(const char *dev, const IP_ADAPTER_ADDRESSES *a)
{
	wchar_t wdev[128] = {0};
	if (dev[0])
		mbstowcs(wdev, dev, sizeof(wdev)/sizeof(wdev[0]) - 1);
	if (a->FriendlyName && _wcsicmp(wdev, a->FriendlyName) == 0)
		return 1;
	if (a->AdapterName && (_stricmp(dev, a->AdapterName) == 0 ||
			       strstr(dev, a->AdapterName)))
		return 1;
	return 0;
}

/* want_configured=1 取"已配置"地址(非fe80/::/::1, 输出字符串);
 * want_configured=0 取链路本地地址(输出16字节)。
 * dev 可为网卡友好名, 也可为 pcap 的 \Device\NPF_{GUID} */
static int find_v6_addr(const char *dev, int want_configured,
			uint8_t raw[16], char *out, size_t outsz)
{
	ULONG size = 0;
	IP_ADAPTER_ADDRESSES *a, *p;
	int found = -1;

	if (GetAdaptersAddresses(AF_INET6, 0, NULL, NULL, &size)
	    != ERROR_BUFFER_OVERFLOW)
		return -1;
	a = (IP_ADAPTER_ADDRESSES *)malloc(size);
	if (!a) return -1;
	if (GetAdaptersAddresses(AF_INET6, 0, NULL, a, &size) != NO_ERROR) {
		free(a);
		return -1;
	}
	for (p = a; p; p = p->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *u;
		if (p->OperStatus != IfOperStatusUp)
			continue;
		if (!adapter_match(dev, p))
			continue;
		for (u = p->FirstUnicastAddress; u; u = u->Next) {
			struct sockaddr_in6 *sa;
			const uint8_t *b;
			if (u->Address.lpSockaddr->sa_family != AF_INET6)
				continue;
			sa = (struct sockaddr_in6 *)u->Address.lpSockaddr;
			b = (const uint8_t *)&sa->sin6_addr;
			if (want_configured ? is_configured_v6(b)
					    : is_linklocal_v6(b)) {
				if (raw) memcpy(raw, b, 16);
				if (out && outsz)
					inet_ntop(AF_INET6, b, out, (int)outsz);
				found = 0;
				goto done;
			}
		}
	}
done:
	free(a);
	return found;
}

#else /* Linux / macOS */

static int find_v6_addr(const char *dev, int want_configured,
			uint8_t raw[16], char *out, size_t outsz)
{
	struct ifaddrs *ifs = NULL, *p;
	int found = -1;

	if (getifaddrs(&ifs) < 0)
		return -1;
	for (p = ifs; p; p = p->ifa_next) {
		struct sockaddr_in6 *sa;
		const uint8_t *b;
		if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET6)
			continue;
		if (dev[0] && strcmp(p->ifa_name, dev) != 0)
			continue;
		sa = (struct sockaddr_in6 *)p->ifa_addr;
		b = (const uint8_t *)&sa->sin6_addr;
		if (want_configured ? is_configured_v6(b)
				    : is_linklocal_v6(b)) {
			if (raw) memcpy(raw, b, 16);
			if (out && outsz)
				inet_ntop(AF_INET6, b, out, (int)outsz);
			found = 0;
			break;
		}
	}
	freeifaddrs(ifs);
	return found;
}
#endif

static int check_configured_v6(const char *dev, char *out, size_t outsz)
{
	return find_v6_addr(dev, 1, NULL, out, outsz);
}

static int get_linklocal_v6(const char *dev, uint8_t ll[16])
{
	return find_v6_addr(dev, 0, ll, NULL, 0);
}

/* ---------- ICMPv6 RS 裸帧构造与发送 ---------- */

static uint16_t onesum(const uint8_t *p, int len)
{
	uint32_t s = 0;
	int i;
	for (i = 0; i + 1 < len; i += 2)
		s += (uint32_t)((p[i] << 8) | p[i+1]);
	if (len & 1)
		s += (uint32_t)p[len-1] << 8;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (uint16_t)s;
}

static void hexdump_tag(const char *tag, const uint8_t *p, unsigned len)
{
	unsigned i;
	printf("%s (%u bytes)\n", tag, len);
	for (i = 0; i < len; i++)
		printf("%02x%s", p[i],
		       (i % 16 == 15) ? "\n" :
		       (i % 8 == 7) ? "  " : " ");
	if (len % 16) printf("\n");
}

/* 发送 ICMPv6 Router Solicitation。
 * 源地址优先用系统在该网卡上的真实链路本地地址并附带 SLLA 选项;
 * 查不到则按 RFC4861 用未指定地址 :: 作源且不带 SLLA(RA 会组播回来)。*/
static void send_rs(pcap_t *h, const uint8_t mac[6], int idx, const char *dev)
{
	static const uint8_t mc[6] = {0x33,0x33,0x00,0x00,0x00,0x02};
	static const uint8_t rtr[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02};
	uint8_t f[70], src[16], pseudo[40];
	unsigned framelen, paylen;
	int have_ll;

	memset(f, 0, sizeof(f));
	memcpy(f+0, mc, 6);                 /* 以太网: 目的 33:33:00:00:00:02 */
	memcpy(f+6, mac, 6);
	f[12] = 0x86; f[13] = 0xdd;

	f[14] = 0x60;                      /* IPv6 基本头 */
	f[20] = 58;                        /* next header = ICMPv6 */
	f[21] = 255;                       /* hop limit = 255 */
	memset(src, 0, sizeof(src));
	have_ll = (get_linklocal_v6(dev, src) == 0);
	memcpy(f+22, src, 16);             /* src = 真实链路本地 或 :: */
	memcpy(f+38, rtr, 16);             /* dst = ff02::2 */

	/* ICMPv6 RS 定长部分: type=133 code=0 cksum reserved(4字节) = 8字节 */
	f[54] = 133; f[55] = 0;
	f[56] = f[57] = 0;
	if (have_ll) {
		/* 源链路层地址选项: type=1 length=1(单位8字节) + MAC */
		f[62] = 1; f[63] = 1;
		memcpy(f+64, mac, 6);
		paylen = 16;
	} else {
		paylen = 8;                     /* 源为 :: 时禁止携带 SLLA */
	}
	f[18] = (uint8_t)(paylen >> 8); f[19] = (uint8_t)paylen;
	framelen = 14 + 40 + paylen;

	/* ICMPv6 校验和(伪首部 + 报文) */
	memset(pseudo, 0, sizeof(pseudo));
	memcpy(pseudo+0,  src, 16);
	memcpy(pseudo+16, rtr, 16);
	pseudo[32] = 0; pseudo[33] = (uint8_t)paylen;
	pseudo[39] = 58;
	{
		uint32_t s = (uint16_t)~onesum(pseudo, 40);
		s += (uint16_t)~onesum(f+54, (int)paylen);
		while (s >> 16) s = (s & 0xffff) + (s >> 16);
		f[56] = (uint8_t)(s >> 8); f[57] = (uint8_t)s;
	}

	if (getenv("X3C_DUMPV6"))
		hexdump_tag("TX ICMPv6-RS", f, framelen);
	if (pcap_sendpacket(h, f, (int)framelen) == 0)
		printf("[v6] 已发送路由器请求 RS #%d (src=%s)\n", idx,
		       have_ll ? "link-local" : "::");
	else
		printf("[v6] RS 发送失败: %s\n", pcap_geterr(h));
}

/* ---------- 系统原生 DHCPv6 续租(后台执行, 不阻塞主循环) ---------- */

static void spawn_renew(const char *dev)
{
#ifdef _WIN32
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char cmd[512];

	(void)dev;   /* Windows 全局执行 ipconfig /renew6, 不区分网卡 */

	snprintf(cmd, sizeof(cmd),
		 "cmd.exe /c ipconfig /renew6 >nul 2>nul");
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
			   CREATE_NO_WINDOW | DETACHED_PROCESS,
			   NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		printf("[v6] 已在后台执行: %s\n", cmd);
	}
#else
	char cmd[640];
	pid_t pid;

	signal(SIGCHLD, SIG_IGN);          /* 子进程自动回收 */
#if defined(__APPLE__)
	snprintf(cmd, sizeof(cmd), "ipconfig set %s AUTOMATIC-V6", dev);
#else
	snprintf(cmd, sizeof(cmd),
		"if command -v rdisc6 >/dev/null 2>&1; then rdisc6 -1 -q %s; fi; "
		"if command -v dhclient >/dev/null 2>&1; then dhclient -6 -1 -nw %s; fi; "
		"if command -v dhcpcd >/dev/null 2>&1; then dhcpcd -6 -n %s; fi",
		dev, dev, dev);
#endif
	pid = fork();
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (pid > 0)
		printf("[v6] 已在后台执行系统续租: %s\n", cmd);
#endif
}

/* ---------- 公共 API / 非阻塞状态机 ---------- */

void x3c_v6kick_init(x3c_v6kick_t *st, int enabled)
{
	memset(st, 0, sizeof(*st));
	st->enabled = enabled;
}

void x3c_v6kick_reset(x3c_v6kick_t *st)
{
	if (!st || !st->enabled) return;
	st->state = KS_OFF;
	st->rs_sent = 0;
	st->renewed = 0;
	st->last_check = 0;
	st->t0 = 0;
}

void x3c_v6kick_start(x3c_v6kick_t *st)
{
	if (!st || !st->enabled || st->state != KS_OFF) return;
	st->state = KS_ACTIVE;
	st->t0 = st->last_check = (int)time(NULL);
	printf("[v6] 认证成功, 开始检测本机 IPv6 地址配置...\n");
}

void x3c_v6kick_tick(x3c_v6kick_t *st, pcap_t *h,
		     const uint8_t mac[6], const char *dev)
{
	static const int rs_delays[V6_RS_COUNT] = V6_RS_DELAYS;
	char addr[INET6_ADDRSTRLEN] = {0};
	int now, elapse, i;

	if (!st || !st->enabled || st->state != KS_ACTIVE)
		return;
	now = (int)time(NULL);
	if (now == st->last_check)
		return;                          /* 1 秒节流 */
	st->last_check = now;
	elapse = now - st->t0;

	if (check_configured_v6(dev, addr, sizeof(addr)) == 0) {
		printf("[v6] 已配置 IPv6 地址: %s (用时 %ds)\n",
		       addr, elapse);
		st->state = KS_OK;
		return;
	}

	for (i = 0; i < V6_RS_COUNT; i++) {
		if (elapse >= rs_delays[i] && st->rs_sent <= i) {
			send_rs(h, mac, i + 1, dev);
			st->rs_sent++;
			break;
		}
	}

	if (elapse >= V6_RENEW_AT && !st->renewed) {
		st->renewed = 1;
		printf("[v6] 仍只有链路本地地址, 尝试触发系统 DHCPv6 续租\n");
		spawn_renew(dev);
	}

	if (elapse >= V6_GIVEUP_AT) {
		printf("[v6] 等待 IPv6 地址超时(%ds), 该网络可能未部署 IPv6\n",
		       V6_GIVEUP_AT);
		st->state = KS_FAIL;
	}
}
