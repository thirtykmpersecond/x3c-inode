/* ipv6.h - 认证成功后的 IPv6 自动配置催促 (非阻塞)
 *
 * 原理(在 H3C 校园网环境抓包验证):
 *   802.1X 认证放行前主机发出的 ICMPv6 RS 会被端口丢弃, 部分系统在网卡
 *   一直 up 的情况下重试间隔很长, 导致认证成功后长时间只有 fe80 链路本地
 *   地址, 拿不到 RA/DHCPv6 下发的地址。
 *   认证成功后主动发一帧 RS(路由器请求), 网关立即回 RA(M=1/O=1),
 *   RA 由内核协议栈自己接收处理, 内核随即发起标准 DHCPv6 四步交互并
 *   安装地址/DNS/路由。本程序绝不自己伪造 DHCPv6(那样租约不会进内核)。
 *
 * 本程序是自由软件, 按 GPLv2+ 许可分发(派生于 njit8021xclient)。
 */
#ifndef X3C_IPV6_H
#define X3C_IPV6_H

#include <stdint.h>
#include <pcap.h>

typedef struct x3c_v6kick {
	int enabled;
	int state;
	int rs_sent;            /* 已发送的 RS 帧数 */
	int renewed;            /* 是否已调用系统续租 */
	int last_check;         /* 上次地址配置检测时刻 */
	int t0;                 /* Success 时刻 */
} x3c_v6kick_t;

void x3c_v6kick_init(x3c_v6kick_t *st, int enabled);

/* 新一轮认证开始时调用(回到 START_AUTHENTICATION 处) */
void x3c_v6kick_reset(x3c_v6kick_t *st);

/* 收到 EAP Success 时调用: 开始计时与检测 */
void x3c_v6kick_start(x3c_v6kick_t *st);

/* 主循环每次迭代调用一次(读超时约 1s, 非阻塞, 内部自行节流) */
void x3c_v6kick_tick(x3c_v6kick_t *st, pcap_t *h,
		     const uint8_t mac[6], const char *dev);

#endif
