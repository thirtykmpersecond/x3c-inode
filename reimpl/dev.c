/* dev.c - 设备信息获取 (跨平台: Linux/macOS/Windows)
 * 对应原二进制中的 dev.c (dev_get_mac / dev_get_ip)
 * Linux  : ioctl SIOCGIFHWADDR / SIOCGIFADDR
 * macOS  : getifaddrs (MAC 用 AF_LINK)
 * Windows: GetAdaptersAddresses (需链接 iphlpapi)
  *
 * 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU 通用公共许可证
 * (GPL)第2版(或你选择的任何更新版本)的条款重新分发和/或修改它。
 * 它派生自 njit8021xclient (GPLv2), 因此按相同许可证分发。
 * 本程序附带希望它有用, 但无任何担保; 详见 LICENSE 文件。
*/
#include <stdio.h>
#include <string.h>
#include "x3c.h"

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

static int find_adapter(PIP_ADAPTER_ADDRESSES a, const char *dev,
			uint8_t mac[6], uint8_t ip[4])
{
	wchar_t wdev[128] = {0};
	if (dev[0])
		mbstowcs(wdev, dev, sizeof(wdev)/sizeof(wdev[0]) - 1);
	for (; a; a = a->Next) {
		int match = 0;
		if (dev[0]) {
			if (a->FriendlyName && _wcsicmp(wdev, a->FriendlyName) == 0)
				match = 1;
			else if (a->AdapterName && (_stricmp(dev, a->AdapterName) == 0 ||
						   strstr(dev, a->AdapterName)))
				match = 1;
			else if (strlen(dev) <= 7 && a->AdapterName &&
				 strncmp(a->AdapterName, dev, strlen(dev)) == 0)
				match = 1;
		} else {
			match = (a->IfType == IF_TYPE_ETHERNET_CSMACD ||
				 a->IfType == IF_TYPE_IEEE80211);
		}
		if (!match || a->OperStatus != IfOperStatusUp)
			continue;
		if (mac && a->PhysicalAddressLength >= 6)
			memcpy(mac, a->PhysicalAddress, 6);
		if (ip) {
			PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress;
			for (; u; u = u->Next) {
				if (u->Address.lpSockaddr->sa_family == AF_INET) {
					struct sockaddr_in *sa =
						(struct sockaddr_in *)u->Address.lpSockaddr;
					memcpy(ip, &sa->sin_addr.s_addr, 4);
					return 0;
				}
			}
		}
		if (mac)
			return 0;
	}
	return -1;
}

int x3c_get_mac(uint8_t mac[6], const char *dev)
{
	ULONG size = 0;
	PIP_ADAPTER_ADDRESSES a;
	int rc;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW)
		return -1;
	a = (PIP_ADAPTER_ADDRESSES)malloc(size);
	if (!a) return -1;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, a, &size) != NO_ERROR) {
		free(a);
		return -1;
	}
	rc = find_adapter(a, dev, mac, NULL);
	free(a);
	return rc;
}

int x3c_get_ip(uint8_t ip[4], const char *dev)
{
	ULONG size = 0;
	PIP_ADAPTER_ADDRESSES a;
	int rc;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW)
		return -1;
	a = (PIP_ADAPTER_ADDRESSES)malloc(size);
	if (!a) return -1;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, a, &size) != NO_ERROR) {
		free(a);
		return -1;
	}
	rc = find_adapter(a, dev, NULL, ip);
	free(a);
	return rc;
}

#elif defined(__APPLE__)
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int find_if(const char *dev, uint8_t mac[6], uint8_t ip[4])
{
	struct ifaddrs *ifs = NULL, *p;
	int got_mac = 0, got_ip = 0;
	if (getifaddrs(&ifs) < 0)
		return -1;
	for (p = ifs; p; p = p->ifa_next) {
		if (!p->ifa_addr) continue;
		if (dev[0] && strcmp(p->ifa_name, dev) != 0) continue;
		if (mac && !got_mac && p->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl *dl = (struct sockaddr_dl *)p->ifa_addr;
			if (dl->sdl_alen >= 6) {
				memcpy(mac, LLADDR(dl), 6);
				got_mac = 1;
			}
		}
		if (ip && !got_ip && p->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sa = (struct sockaddr_in *)p->ifa_addr;
			memcpy(ip, &sa->sin_addr.s_addr, 4);
			got_ip = 1;
		}
		if ((!mac || got_mac) && (!ip || got_ip))
			break;
	}
	freeifaddrs(ifs);
	if (mac && !got_mac) return -1;
	if (ip && !got_ip) return -1;
	return 0;
}

int x3c_get_mac(uint8_t mac[6], const char *dev)
{
	return find_if(dev, mac, NULL);
}

int x3c_get_ip(uint8_t ip[4], const char *dev)
{
	return find_if(dev, NULL, ip);
}

#else /* Linux */
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int x3c_get_mac(uint8_t mac[6], const char *dev)
{
	int fd;
	struct ifreq ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		close(fd);
		return -1;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
	return 0;
}

int x3c_get_ip(uint8_t ip[4], const char *dev)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sa;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFADDR)");
		close(fd);
		return -1;
	}
	sa = (struct sockaddr_in *)&ifr.ifr_addr;
	memcpy(ip, &sa->sin_addr.s_addr, 4);
	close(fd);
	return 0;
}
#endif