/* compat.h - 跨平台兼容层 (Windows: 自带 getopt_long; 其余用系统版本)  *
 * 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU 通用公共许可证
 * (GPL)第2版(或你选择的任何更新版本)的条款重新分发和/或修改它。
 * 它派生自 njit8021xclient (GPLv2), 因此按相同许可证分发。
 * 本程序附带希望它有用, 但无任何担保; 详见 LICENSE 文件。
*/
#ifndef X3C_COMPAT_H
#define X3C_COMPAT_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

typedef struct x3c_option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
} x3c_option;
#define option          x3c_option
#define no_argument     0
#define required_argument 1
#define optional_argument 2
extern int x3c_optind;
extern int x3c_optopt;
extern char *x3c_optarg;
int x3c_getopt_long(int argc, char *const argv[], const char *optstring,
		    const x3c_option *longopts, int *longindex);
#define optind  x3c_optind
#define optopt  x3c_optopt
#define optarg  x3c_optarg
#define getopt_long x3c_getopt_long

#define x3c_sleep(s) Sleep((s) * 1000)
#define x3c_wsa_init() do { WSADATA w; WSAStartup(MAKEWORD(2,2), &w); \
	SetConsoleOutputCP(CP_UTF8); SetConsoleCP(CP_UTF8); } while (0)

#else
#include <unistd.h>
#define x3c_sleep(s) sleep(s)
#define x3c_wsa_init() do {} while (0)
#endif

#endif