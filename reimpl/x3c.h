/* x3c.h - 共用声明与配置结构  *
 * 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU 通用公共许可证
 * (GPL)第2版(或你选择的任何更新版本)的条款重新分发和/或修改它。
 * 它派生自 njit8021xclient (GPLv2), 因此按相同许可证分发。
 * 本程序附带希望它有用, 但无任何担保; 详见 LICENSE 文件。
*/
#ifndef X3C_H
#define X3C_H

#include <stddef.h>
#include <stdint.h>

#define H3C_KEY_OLD "HuaWei3COM1X"
#define H3C_KEY_NEW "Oly5D62FaE94W7"
#define PRIVIKEY_DEFAULT "1234567890123456"
#define BUILTIN_VERSION "EN V3.60-6208"

typedef struct {
	char username[64];
	char password[64];
	char iface[64];       /* -I 认证网卡 */
	char assitif[64];     /* -A 辅助接口(取IP用,可空) */
	char privikey[64];    /* -P 私钥 */
	char version[20];     /* -V 上报版本串 */
	int  xorkey;          /* -x 0=老版密钥 1=新版密钥 */
	int  mcast;           /* -m 多播应答 */
	int  ipcommit;        /* -i 提交WAN口IP */
	int  vercommit;       /* -v 提交版本号 */
	int  md5ver;          /* -M 0=标准 1=部分高校 */
} x3c_cfg_t;

void x3c_md5(const void *in, size_t len, uint8_t out[16]);
void x3c_fill_md5(uint8_t digest[16], uint8_t id, const char *passwd,
		  const uint8_t challenge[16], int md5ver);
int  x3c_get_mac(uint8_t mac[6], const char *dev);
int  x3c_get_ip(uint8_t ip[4], const char *dev);
int  x3c_authenticate(const x3c_cfg_t *cfg);

const char *x3c_xor_key(const x3c_cfg_t *cfg);

#endif