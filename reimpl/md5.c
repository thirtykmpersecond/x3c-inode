/* md5.c - RFC1321 MD5, 自包含实现(不依赖 openssl)
 * 对应原二进制中的 md5.c
  *
 * 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU 通用公共许可证
 * (GPL)第2版(或你选择的任何更新版本)的条款重新分发和/或修改它。
 * 它派生自 njit8021xclient (GPLv2), 因此按相同许可证分发。
 * 本程序附带希望它有用, 但无任何担保; 详见 LICENSE 文件。
*/
#include <stdint.h>
#include <string.h>
#include "x3c.h"

static const uint32_t K[64] = {
	0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
	0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
	0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
	0x6b901122,0xfd987193,0xa679438e,0x49b40821,
	0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
	0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
	0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
	0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
	0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
	0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
	0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
	0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
	0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
	0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
	0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
	0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t S[64] = {
	 7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
	 5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
	 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
	 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};
static uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
	uint32_t M[16];
	int i;
	for (i=0;i<16;i++) {
		M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
		       ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
	}
	for (i=0;i<64;i++) {
		uint32_t f; int g;
		if (i<16)      { f=(b&c)|(~b&d);       g=i; }
		else if (i<32) { f=(d&b)|(~d&c);       g=(5*i+1)&15; }
		else if (i<48) { f=b^c^d;              g=(3*i+5)&15; }
		else           { f=c^(b|~d);           g=(7*i)&15; }
		uint32_t tmp = d; d=c; c=b;
		b = b + rol(a + f + K[i] + M[g], S[i]);
		a = tmp;
	}
	state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}

void x3c_md5(const void *in, size_t len, uint8_t out[16])
{
	uint32_t state[4] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476};
	const uint8_t *p = in;
	uint64_t bitlen = (uint64_t)len << 3;
	size_t i = 0;
	while (i + 64 <= len) { md5_transform(state, p+i); i += 64; }
	uint8_t tail[128];
	size_t rem = len - i;
	memcpy(tail, p+i, rem);
	tail[rem] = 0x80;
	size_t padlen = (rem < 56) ? 64 : 128;
	memset(tail+rem+1, 0, padlen - rem - 1 - 8);
	for (i=0;i<8;i++) tail[padlen-8+i] = (uint8_t)(bitlen >> (8*i));
	for (i=0;i+64<=padlen;i+=64) md5_transform(state, tail+i);
	for (i=0;i<4;i++) {
		out[i*4]   = (uint8_t)state[i];
		out[i*4+1] = (uint8_t)(state[i]>>8);
		out[i*4+2] = (uint8_t)(state[i]>>16);
		out[i*4+3] = (uint8_t)(state[i]>>24);
	}
}

/* 标准 EAP-MD5 应答摘要: MD5(id + password + challenge), 16字节
 * md5ver=1(部分高校变体): 密码先取 MD5 再参与运算(需实测确认) */
void x3c_fill_md5(uint8_t digest[16], uint8_t id, const char *passwd,
		  const uint8_t challenge[16], int md5ver)
{
	uint8_t msgbuf[160];
	size_t passlen, msglen;

	if (md5ver == 1) {
		uint8_t h[16];
		x3c_md5(passwd, strlen(passwd), h);
		msgbuf[0] = id;
		memcpy(msgbuf+1, h, 16);
		memcpy(msgbuf+17, challenge, 16);
		msglen = 33;
	} else {
		passlen = strlen(passwd);
		msgbuf[0] = id;
		memcpy(msgbuf+1, passwd, passlen);
		memcpy(msgbuf+1+passlen, challenge, 16);
		msglen = 1 + passlen + 16;
	}
	x3c_md5(msgbuf, msglen, digest);
}