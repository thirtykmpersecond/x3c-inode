/* x3c.c - H3C/iNode 802.1X 客户端 (重写版)
 *
 * 根据对极路由固件 /usr/sbin/x3c8021x 二进制逆向分析,
 * 在开源 njit8021xclient 协议核心的基础上重写,
 * 恢复 HiWiFi 版命令行接口与全部可配置项:
 *   -u 用户名  -p 密码  -I 认证网卡
 *   -x xorkey   0=老版密钥(HuaWei3COM1X) 1=新版密钥(Oly5D62FaE94W7)
 *   -m mcast    0=单播应答 1=多播应答
 *   -i ipcommit 0/1 是否提交IP给服务器
 *   -v vercommit 0/1 是否提交版本号给服务器
 *   -A assitif  辅助接口(用于取IP,可空)
 *   -P privikey 私钥(缺省 1234567890123456 = 自动,用xorkey所选密钥)
 *   -M md5ver   0=标准EAP-MD5 1=部分高校变体(密码先MD5,需抓包确认)
 *   -V version  上报版本串, 如 'CH\x11V7.xx-yyyy' 或 'CH V3.60-6208'
 *
 * 协议状态机与报文格式与 njit8021xclient 一致(已核对二进制日志串),
 * 内置默认版本串 "EN V3.60-6208"(与二进制一致)。
 *
 * 本程序为自由软件,按 GPLv2+ 许可分发(派生于 njit8021xclient)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#ifndef _WIN32
#include <getopt.h>
#include <arpa/inet.h>
#endif
#include <pcap.h>
#include "x3c.h"
#include "compat.h"

/* 原二进制会把认证过程打印到 stderr(init 重定向到日志文件), 故默认开启日志;
 * 编译时加 -DNDEBUG 可关闭 */
#ifdef NDEBUG
# define DPRINTF(...) ((void)0)
#else
# define DPRINTF(...) printf(__VA_ARGS__)
#endif

typedef enum { EAP_REQUEST=1, EAP_RESPONSE=2, EAP_SUCCESS=3,
	       EAP_FAILURE=4, EAP_H3CDATA=0x0A } eap_code_t;
typedef enum { EAP_IDENTITY=1, EAP_NOTIFICATION=2, EAP_MD5=4,
	       EAP_PLAINTEXT=7, EAP_AVAILABLE=20 } eap_type_t;

static void hexdump(const char *tag, const uint8_t *p, unsigned len);

__attribute__((unused))
static const uint8_t BC_ADDR[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
__attribute__((unused))
static const uint8_t MC_ADDR[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03};
/* 华三私有多播: iNode 抓包确认 EAPOL-Start/Logoff 发往此地址 */
static const uint8_t H3C_ADDR[6] = {0x01,0xd0,0xf8,0x00,0x00,0x03};

const char *x3c_xor_key(const x3c_cfg_t *cfg)
{
	if (cfg->privikey[0] && strcmp(cfg->privikey, PRIVIKEY_DEFAULT) != 0)
		return cfg->privikey;
	return cfg->xorkey ? H3C_KEY_NEW : H3C_KEY_OLD;
}

static void XOR(uint8_t *data, unsigned dlen, const char *key, unsigned klen)
{
	unsigned i, j;
	for (i=0; i<dlen; i++) data[i] ^= key[i%klen];
	for (i=dlen-1,j=0; j<dlen; i--,j++) data[i] ^= key[j%klen];
}

/* 客户端版本区: 16字节版本串(第一轮XOR RandomKey) + 4字节random(第二轮XOR H3C密钥) */
static void fill_client_version_area(uint8_t area[20], const x3c_cfg_t *cfg)
{
	uint32_t random = 22222222;
	char rk[9];

	random += (uint32_t)time(NULL) + 12121212;
	snprintf(rk, sizeof(rk), "%08x", random);

	memset(area, 0, 16);
	memcpy(area, cfg->version[0] ? cfg->version : BUILTIN_VERSION, 15);
	XOR(area, 16, rk, strlen(rk));

	random = htonl(random);
	memcpy(area+16, &random, 4);

	XOR(area, 20, x3c_xor_key(cfg), strlen(x3c_xor_key(cfg)));
}

/* Windows 操作系统版本区: 20字节 "r70393861" XOR H3C密钥(与二进制一致) */
static void fill_windows_version_area(uint8_t area[20], const x3c_cfg_t *cfg)
{
	static const uint8_t win[20] = "r70393861";
	memcpy(area, win, 20);
	XOR(area, 20, x3c_xor_key(cfg), strlen(x3c_xor_key(cfg)));
}

/* 28字节 Base64(内含FillClientVersionArea的20字节) */
static void fill_base64_area(char area[28], const x3c_cfg_t *cfg)
{
	uint8_t version[20];
	static const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				  "abcdefghijklmnopqrstuvwxyz"
				  "0123456789+/";
	uint8_t c1,c2,c3;
	int i=0, j=0;

	fill_client_version_area(version, cfg);
	while (j < 24) {
		c1 = version[i++]; c2 = version[i++]; c3 = version[i++];
		area[j++] = Tbl[ (c1&0xfc)>>2 ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
		area[j++] = Tbl[((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[ c3&0x3f ];
	}
	c1 = version[i++]; c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[ (c2&0x0f)<<2 ];
	area[27] = '=';
}

static void send_start_pkt(pcap_t *h, const uint8_t mac[6])
{
	uint8_t p[64];
	memset(p, 0, sizeof(p));
	memcpy(p, H3C_ADDR, 6);
	memcpy(p+6, mac, 6);
	p[12]=0x88; p[13]=0x8e;
	p[14]=0x01; p[15]=0x01; p[16]=0x00; p[17]=0x00;
	hexdump("TX Start", p, sizeof(p));
	pcap_sendpacket(h, p, sizeof(p));
}

static void send_logoff_pkt(pcap_t *h, const uint8_t mac[6])
{
	uint8_t p[64];
	memset(p, 0, sizeof(p));
	memcpy(p, H3C_ADDR, 6);
	memcpy(p+6, mac, 6);
	p[12]=0x88; p[13]=0x8e;
	p[14]=0x01; p[15]=0x02; p[16]=0x00; p[17]=0x00;
	pcap_sendpacket(h, p, sizeof(p));
	DPRINTF(">>Client: Logoff.\n");
}

/* Response Identity: [0x15 IP][0x06 版本][2空格][用户名] */
static void send_response_identity(pcap_t *h, const uint8_t req[],
	const uint8_t ethhdr[], const uint8_t ip[4],
	const x3c_cfg_t *cfg)
{
	uint8_t r[128];
	uint16_t eaplen;
	size_t i, ulen;

	memcpy(r, ethhdr, 14);
	r[14]=0x01; r[15]=0x00;                 /* 802.1X Version/Type */
	r[18]=EAP_RESPONSE; r[19]=req[19]; r[22]=EAP_IDENTITY;
	i = 23;
	if (cfg->ipcommit) {                    /* 0x15 提交IP */
		r[i++]=0x15; r[i++]=0x04;
		memcpy(r+i, ip, 4); i += 4;
	}
	if (cfg->vercommit) {                   /* 0x06 提交版本 */
		r[i++]=0x06; r[i++]=0x07;
		fill_base64_area((char*)r+i, cfg); i += 28;
	}
	r[i++]=' '; r[i++]=' ';
	ulen = strlen(cfg->username);
	memcpy(r+i, cfg->username, ulen); i += ulen;
	assert(i <= sizeof(r));

	eaplen = htons(i-18);
	memcpy(r+16, &eaplen, 2);
	memcpy(r+20, &eaplen, 2);
	hexdump("TX Response-Identity", r, (unsigned)i);
	pcap_sendpacket(h, r, i);
}

/* Response Available: [0x00代理][0x15 IP][0x06版本][2空格][用户名] */
static void send_response_available(pcap_t *h, const uint8_t req[],
	const uint8_t ethhdr[], const uint8_t ip[4],
	const x3c_cfg_t *cfg)
{
	uint8_t r[128];
	uint16_t eaplen;
	size_t i, ulen;

	memcpy(r, ethhdr, 14);
	r[14]=0x01; r[15]=0x00;
	r[18]=EAP_RESPONSE; r[19]=req[19]; r[22]=EAP_AVAILABLE;
	i = 23;
	r[i++] = 0x00;                          /* 是否使用代理 */
	r[i++]=0x15; r[i++]=0x04;
	memcpy(r+i, ip, 4); i += 4;
	r[i++]=0x06; r[i++]=0x07;
	fill_base64_area((char*)r+i, cfg); i += 28;
	r[i++]=' '; r[i++]=' ';
	ulen = strlen(cfg->username);
	memcpy(r+i, cfg->username, ulen); i += ulen;
	assert(i <= sizeof(r));

	eaplen = htons(i-18);
	memcpy(r+16, &eaplen, 2);
	memcpy(r+20, &eaplen, 2);
	pcap_sendpacket(h, r, i);
}

/* Response MD5-Challenge */
/* Response 明文密码 (EAP type 0x07, H3C 私有):
 * [密码长度1字节][密码][用户名]
 * 载荷布局: 0x07 <passlen> <password> <username>，EAP len = total-18。
 * （H3C 部分校园网部署使用，非标准 EAP-MD5。实际长度字节以抓包为准。）*/
static void send_response_plaintext(pcap_t *h, const uint8_t req[],
	const uint8_t ethhdr[], const x3c_cfg_t *cfg)
{
	uint8_t r[128];
	uint16_t eaplen;
	size_t i, plen, ulen;

	memcpy(r, ethhdr, 14);
	r[14]=0x01; r[15]=0x00;
	r[18]=EAP_RESPONSE; r[19]=req[19]; r[22]=EAP_PLAINTEXT;
	i = 23;
	plen = strlen(cfg->password);
	r[i++] = (uint8_t)plen;
	memcpy(r+i, cfg->password, plen); i += plen;
	ulen = strlen(cfg->username);
	memcpy(r+i, cfg->username, ulen); i += ulen;
	assert(i <= sizeof(r));

	eaplen = htons((uint16_t)(i-18));
	memcpy(r+16, &eaplen, 2);
	memcpy(r+20, &eaplen, 2);
	hexdump("TX Response-Plaintext", r, (unsigned)i);
	pcap_sendpacket(h, r, i);
}

static void send_response_md5(pcap_t *h, const uint8_t req[],
	const uint8_t ethhdr[], const x3c_cfg_t *cfg)
{
	uint8_t r[128];
	uint16_t eaplen;
	size_t ulen, plen;
	int i;

	ulen = strlen(cfg->username);
	eaplen = htons(22 + ulen);
	plen = 14 + 4 + 22 + ulen;

	memcpy(r, ethhdr, 14);
	r[14]=0x01; r[15]=0x00;
	memcpy(r+16, &eaplen, 2);
	r[18]=EAP_RESPONSE; r[19]=req[19];
	r[20]=r[16]; r[21]=r[17];
	r[22]=EAP_MD5; r[23]=16;
	x3c_fill_md5(r+24, req[19], cfg->password, req+24, cfg->md5ver);
	memcpy(r+40, cfg->username, ulen);
	for (i=0; i<10; i++) r[plen++]=0x00;
	pcap_sendpacket(h, r, plen);
}

/* Response Notification: 客户端版本 + Windows版本 */
static void send_response_notification(pcap_t *h, const uint8_t req[],
	const uint8_t ethhdr[], const x3c_cfg_t *cfg)
{
	uint8_t r[67];
	int i;

	memcpy(r, ethhdr, 14);
	r[14]=0x01; r[15]=0x00;
	r[16]=0x00; r[17]=0x31;
	r[18]=EAP_RESPONSE; r[19]=req[19];
	r[20]=r[16]; r[21]=r[17];
	r[22]=EAP_NOTIFICATION;

	i = 23;
	r[i++]=0x01; r[i++]=22;
	fill_client_version_area(r+i, cfg); i += 20;
	r[i++]=0x02; r[i++]=22;
	fill_windows_version_area(r+i, cfg); i += 20;
	pcap_sendpacket(h, r, sizeof(r));
}

#ifdef _WIN32
static const char *resolve_pcap_dev(const char *dev);
#endif

static char g_logfile[256];
static int g_dump;
static int g_sniff;

/* -d: 十六进制转储收发的原始帧 */
static void hexdump(const char *tag, const uint8_t *p, unsigned len)
{
	unsigned i;
	if (!g_dump) return;
	printf("--- %s (%u bytes) ---\n", tag, len);
	for (i = 0; i < len; i++) {
		printf("%02x%s", p[i],
		       (i % 16 == 15) ? "\n" : ((i % 8 == 7) ? "  " : " "));
	}
	if (len % 16) printf("\n");
}

/* 解析 -V 参数里的 \xNN 转义(版本串 V7 格式的分隔符是 0x11, 命令行没法直接输入) */
static void unescape(char *dst, size_t dsz, const char *src)
{
	size_t i = 0;
	while (*src && i + 1 < dsz) {
		if (src[0] == '\\' && (src[1] == 'x' || src[1] == 'X') &&
		    isxdigit((unsigned char)src[2]) && isxdigit((unsigned char)src[3])) {
			char hex[3] = { src[2], src[3], 0 };
			dst[i++] = (char)strtol(hex, NULL, 16);
			src += 4;
		} else {
			dst[i++] = *src++;
		}
	}
	dst[i] = '\0';
}

#ifdef _WIN32
static LONG WINAPI crash_handler(EXCEPTION_POINTERS *ep)
{
	fprintf(stderr, "FATAL: exception code 0x%08lX at %p\n",
		ep->ExceptionRecord->ExceptionCode,
		ep->ExceptionRecord->ExceptionAddress);
	fflush(stderr);
	return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static const char *ip_iface(const x3c_cfg_t *cfg)
{
#ifdef _WIN32
	return resolve_pcap_dev(cfg->assitif[0] ? cfg->assitif : cfg->iface);
#else
	return cfg->assitif[0] ? cfg->assitif : cfg->iface;
#endif
}

/* Windows: 把 -I 填的网卡名/描述/AdapterName GUID 解析成 pcap 设备名 \Device\NPF_{GUID} */
#ifdef _WIN32
static const char *resolve_pcap_dev(const char *dev)
{
	static char buf[512];
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!dev[0]) return dev;
	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		return dev;
	}
	for (d = alldevs; d; d = d->next) {
		if (!d->name) continue;
		if (strstr(d->name, dev) ||
		    (d->description && strstr(d->description, dev))) {
			strncpy(buf, d->name, sizeof(buf)-1);
			pcap_freealldevs(alldevs);
			return buf;
		}
	}
	fprintf(stderr, "未找到匹配 '%s' 的抓包设备\n", dev);
	pcap_freealldevs(alldevs);
	return dev;
}
#endif

/* -l: 枚举抓包设备 (Windows 下附带适配器友好名与MAC对照) */
static int list_devices(void)
{
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
	printf("== 抓包设备 (pcap) ==\n");
	for (d = alldevs; d; d = d->next) {
		printf("[%d] %s\n", i++, d->name);
		if (d->description)
			printf("    desc: %s\n", d->description);
	}
	pcap_freealldevs(alldevs);
#ifdef _WIN32
	{
		ULONG size = 0;
		PIP_ADAPTER_ADDRESSES a, p;
		GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
		a = (PIP_ADAPTER_ADDRESSES)malloc(size);
		if (a && GetAdaptersAddresses(AF_UNSPEC, 0, NULL, a, &size) == NO_ERROR) {
			printf("== 系统适配器 (GetAdaptersAddresses) ==\n");
			for (p = a; p; p = p->Next) {
				uint8_t m[6] = {0};
				if (p->PhysicalAddressLength >= 6)
					memcpy(m, p->PhysicalAddress, 6);
				printf("%ls  MAC=%02x:%02x:%02x:%02x:%02x:%02x  name=%s\n",
					p->FriendlyName ? p->FriendlyName : L"?",
					m[0],m[1],m[2],m[3],m[4],m[5],
					p->AdapterName ? p->AdapterName : "");
			}
		}
		free(a);
	}
#endif
	return 0;
}

static pcap_t *g_handle;
static uint8_t g_mac[6];

/* -S: 只监听不认证, 转储网卡上所有 EAPOL 帧(用于抓 iNode 等客户端的正确报文对比) */
static int sniff_eapol(const x3c_cfg_t *cfg)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	const uint8_t *cap;
	const char *capdev;
	uint8_t mac[6];
	pcap_t *h;

#ifdef _WIN32
	capdev = resolve_pcap_dev(cfg->iface);
#else
	capdev = cfg->iface;
#endif
	h = pcap_open_live(capdev, 65536, 1, 1000, errbuf);
	if (!h) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return -1;
	}
	if (x3c_get_mac(mac, capdev) < 0) {
		fprintf(stderr, "get MAC failed for '%s'\n", capdev);
		return -1;
	}
	printf("sniff: device=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n", capdev,
	       mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	printf("监听 EAPOL(0x888e) 中, 现在用 iNode 认证一次, Ctrl-C 结束\n");
	if (pcap_compile(h, &fcode, "ether proto 0x888e", 1, 0xff) < 0 ||
	    pcap_setfilter(h, &fcode) < 0) {
		fprintf(stderr, "filter: %s\n", pcap_geterr(h));
		return -1;
	}
	g_dump = 1;
	for (;;) {
		int rc = pcap_next_ex(h, &header, &cap);
		if (rc != 1)
			continue;
		hexdump(memcmp(cap+6, mac, 6) == 0 ? "TX(client->switch)"
						   : "RX(switch->client)",
			cap, header->caplen);
	}
}

static void on_sigint(int sig)
{
	(void)sig;
	send_logoff_pkt(g_handle, g_mac);
	exit(0);
}

int x3c_authenticate(const x3c_cfg_t *cfg)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter[100];
	struct bpf_program fcode;
	pcap_t *h;
	uint8_t mac[6];
	const char *capdev;

	printf("[0] auth: iface='%s' assoif='%s'\n", cfg->iface, cfg->assitif);
#ifdef _WIN32
	capdev = resolve_pcap_dev(cfg->iface);
#else
	capdev = cfg->iface;
#endif
	printf("[0] auth: resolve -> '%s'\n", capdev);
	fflush(stderr);
	g_handle = h = pcap_open_live(capdev, 65536, 1, 1000, errbuf);
	if (!h) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return -1;
	}
	printf("[0] auth: pcap_open_live ok\n");
	fflush(stderr);
	if (x3c_get_mac(mac, capdev) < 0) {
		fprintf(stderr, "get MAC failed for '%s'\n", capdev);
		return -1;
	}
	memcpy(g_mac, mac, 6);
	printf("[0] device: %s\n", capdev);
	printf("[0] mac:    %02x:%02x:%02x:%02x:%02x:%02x\n",
	       mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	fflush(stderr);
	signal(SIGINT, on_sigint);

	snprintf(filter, sizeof(filter),
		 "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)%s",
		 mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],
		 cfg->mcast ? " or (ether dst 01:80:c2:00:00:03)" : "");
	if (pcap_compile(h, &fcode, filter, 1, 0xff) < 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(h));
		return -1;
	}
	if (pcap_setfilter(h, &fcode) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(h));
		return -1;
	}

START_AUTHENTICATION:
	{
		int start_count = 0;
		struct pcap_pkthdr *header;
		const uint8_t *cap;
		uint8_t ethhdr[14] = {0};
		uint8_t ip[4] = {0};

		send_start_pkt(h, mac);
		DPRINTF("[0] Client: Start.\n");

		for (;;) {
			int rc = pcap_next_ex(h, &header, &cap);
			if (rc == 1) hexdump("RX(start-wait)", cap, header->caplen);
			if (rc == 1 && (eap_code_t)cap[18] == EAP_REQUEST)
				break;
			DPRINTF(".");
			send_start_pkt(h, mac);
			if (start_count++ > 10) {
				DPRINTF("\nServer is not responding...\n");
				goto START_AUTHENTICATION;
			}
		}
		if (start_count) DPRINTF("\n");

		memcpy(ethhdr+0, cap+6, 6);
		memcpy(ethhdr+6, mac, 6);
		ethhdr[12]=0x88; ethhdr[13]=0x8e;

		if ((eap_type_t)cap[22] == EAP_IDENTITY) {
			DPRINTF("[%d] Server: Request Identity!\n", cap[19]);
			if (cfg->ipcommit) x3c_get_ip(ip, ip_iface(cfg));
			send_response_identity(h, cap, ethhdr, ip, cfg);
			DPRINTF("[%d] Client: Response Identity.\n", cap[19]);
		}

		snprintf(filter, sizeof(filter),
			 "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			 cap[6],cap[7],cap[8],cap[9],cap[10],cap[11]);
		pcap_compile(h, &fcode, filter, 1, 0xff);
		pcap_setfilter(h, &fcode);

		for (;;) {
			int idle = 0;
			while (pcap_next_ex(h, &header, &cap) != 1) {
				DPRINTF(".");
				/* 读超时已是1s, 这里不再额外sleep */
				if (++idle > 15) {
					DPRINTF("\nWait for handshake package timed out...\n");
					goto START_AUTHENTICATION;
				}
			}
			if (idle) DPRINTF("\n");
			hexdump("RX", cap, header->caplen);

			if ((eap_code_t)cap[18] == EAP_REQUEST) {
				switch ((eap_type_t)cap[22]) {
				case EAP_IDENTITY:
					DPRINTF("[%d] Server: Request Identity!\n", cap[19]);
					if (cfg->ipcommit) x3c_get_ip(ip, ip_iface(cfg));
					send_response_identity(h, cap, ethhdr, ip, cfg);
					DPRINTF("[%d] Client: Response Identity.\n", cap[19]);
					break;
				case EAP_AVAILABLE:
					DPRINTF("[%d] Server: Request AVAILABLE!\n", cap[19]);
					if (cfg->ipcommit) x3c_get_ip(ip, ip_iface(cfg));
					send_response_available(h, cap, ethhdr, ip, cfg);
					DPRINTF("[%d] Client: Response AVAILABLE.\n", cap[19]);
					break;
				case EAP_MD5:
					DPRINTF("[%d] Server: Request MD5-Challenge!\n", cap[19]);
					send_response_md5(h, cap, ethhdr, cfg);
					DPRINTF("[%d] Client: Response MD5-Challenge.\n", cap[19]);
					break;
				case EAP_PLAINTEXT:
					DPRINTF("[%d] Server: Request Plaintext-Password!\n", cap[19]);
					send_response_plaintext(h, cap, ethhdr, cfg);
					DPRINTF("[%d] Client: Response Plaintext-Password.\n", cap[19]);
					break;
				case EAP_NOTIFICATION:
					DPRINTF("[%d] Server: Request Notification!\n", cap[19]);
					send_response_notification(h, cap, ethhdr, cfg);
					DPRINTF("     Client: Response Notification.\n");
					break;
				default:
					DPRINTF("[%d] Server: Request (type:%d)!\n",
						cap[19], (eap_type_t)cap[22]);
					DPRINTF("Error! Unexpected request type\n");
					return -1;
				}
			} else if ((eap_code_t)cap[18] == EAP_FAILURE) {
				uint8_t errtype = cap[22], msgsize = cap[23];
				const char *msg = (const char*)&cap[24];
				DPRINTF("[%d] Server: Failure.\n", cap[19]);
				if (errtype==0x09 && msgsize>0) {
					fprintf(stderr, "%s\n", msg);
					/* E2531用户名不存在 E2542已在线 E2553密码错 E3137版本无效 */
					return -1;
				} else if (errtype==0x08) {
					goto START_AUTHENTICATION;
				} else {
					DPRINTF("errtype=0x%02x\n", errtype);
					return -1;
				}
			} else if ((eap_code_t)cap[18] == EAP_SUCCESS) {
				DPRINTF("[%d] Server: Success.\n", cap[19]);
			} else {
				DPRINTF("[%d] Server: (H3C private data) "
					"%02x %02x %02x %02x %02x\n", cap[19],
					cap[22], cap[23], cap[24], cap[25], cap[26]);
			}
		}
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s -u 用户名 -p 密码 -I 网卡 [选项]\n"
		"  -u 用户名\n"
		"  -p 密码\n"
		"  -I 认证网卡(如 eth3)\n"
		"  -x xorkey    0=老版密钥(HuaWei3COM1X) 1=新版密钥(Oly5D62FaE94W7)\n"
		"  -m mcast     0=单播应答 1=多播应答\n"
		"  -i ipcommit  0/1 提交WAN口IP给服务器\n"
		"  -v vercommit 0/1 提交版本号给服务器\n"
		"  -A assitif   辅助接口(用于取IP,可空)\n"
		"  -P privikey  私钥(缺省自动)\n"
		"  -M md5ver    0=标准EAP-MD5 1=部分高校变体(需抓包确认)\n"
		"  -V version   上报版本串, 如 'CH\\x11V7.30-0548' 或 'CH V3.60-6208'\n"
		"  -l 枚举抓包设备(先运行此参数查看 -I 应填什么)\n"
		"  -L file 把输出写入日志文件\n"
		"  -d 转储收发的原始帧(排障用)\n"
		"  -S 只监听不认证, 抓 iNode 等客户端的报文做对比\n"
		"  -h 帮助\n"
		"示例: %s -u <用户名> -p <密码> -I eth3 -x 1 -m 0 -i 0 -v 1 "
		"-V 'CH\\x11V7.30-0548'\n",
		prog, prog);
}

int main(int argc, char *argv[])
{
	x3c_cfg_t cfg;
	int c;

	setvbuf(stdout, NULL, _IONBF, 0);
	x3c_wsa_init();
#ifdef _WIN32
	SetUnhandledExceptionFilter(crash_handler);
#endif
#ifndef _WIN32
	if (getuid() != 0) {
		fprintf(stderr, "%s: need root privilege!!!\n", argv[0]);
		return -1;
	}
#endif

	memset(&cfg, 0, sizeof(cfg));
	cfg.xorkey = 1;
	cfg.ipcommit = 1;
	cfg.vercommit = 1;

	while ((c = getopt_long(argc, argv, "u:p:I:x:m:i:v:A:P:M:V:hL:ldS",
			 (const struct option[]){
				{"username",  required_argument, 0, 'u'},
				{"password",  required_argument, 0, 'p'},
				{"interface", required_argument, 0, 'I'},
				{"xorkey",    required_argument, 0, 'x'},
				{"mcast",     required_argument, 0, 'm'},
				{"ipcommit",  required_argument, 0, 'i'},
				{"vercommit", required_argument, 0, 'v'},
				{"assitif",   required_argument, 0, 'A'},
				{"privikey",  required_argument, 0, 'P'},
				{"md5ver",    required_argument, 0, 'M'},
				{"version",   required_argument, 0, 'V'},
				{"help",      no_argument,       0, 'h'},
				{"list",      no_argument,       0, 'l'},
				{"log",       required_argument, 0, 'L'},
				{"dump",      no_argument,       0, 'd'},
				{"sniff",     no_argument,       0, 'S'},
				{0,0,0,0}
			 }, NULL)) != -1) {
		switch (c) {
		case 'u': strncpy(cfg.username, optarg, sizeof(cfg.username)-1); break;
		case 'p': strncpy(cfg.password, optarg, sizeof(cfg.password)-1); break;
		case 'I': strncpy(cfg.iface,   optarg, sizeof(cfg.iface)-1);   break;
		case 'x': cfg.xorkey    = atoi(optarg); break;
		case 'm': cfg.mcast     = atoi(optarg); break;
		case 'i': cfg.ipcommit  = atoi(optarg); break;
		case 'v': cfg.vercommit = atoi(optarg); break;
		case 'A': strncpy(cfg.assitif,  optarg, sizeof(cfg.assitif)-1);  break;
		case 'P': strncpy(cfg.privikey, optarg, sizeof(cfg.privikey)-1); break;
		case 'M': cfg.md5ver = atoi(optarg); break;
		case 'V': unescape(cfg.version, sizeof(cfg.version), optarg); break;
		case 'L': strncpy(g_logfile, optarg, sizeof(g_logfile)-1); break;
		case 'd': g_dump = 1; break;
		case 'S': g_sniff = 1; break;
		case 'l': return list_devices();
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return -1;
		}
	}

	if (!cfg.username[0] || !cfg.password[0] || !cfg.iface[0]) {
		usage(argv[0]);
		return -1;
	}

	if (g_logfile[0]) {
		if (freopen(g_logfile, "w", stdout)) {
			FILE *lf = freopen(g_logfile, "a", stderr);
			(void)lf;
		}
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	printf("x3c8021x-re (reimpl) built " __DATE__ "\n");

	if (g_sniff)
		return sniff_eapol(&cfg);

	return x3c_authenticate(&cfg);
}