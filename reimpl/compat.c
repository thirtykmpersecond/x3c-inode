/* compat.c - Windows 版 getopt_long(参数解析), 支持短选项/长选项/缩写  *
 * 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU 通用公共许可证
 * (GPL)第2版(或你选择的任何更新版本)的条款重新分发和/或修改它。
 * 它派生自 njit8021xclient (GPLv2), 因此按相同许可证分发。
 * 本程序附带希望它有用, 但无任何担保; 详见 LICENSE 文件。
*/
#ifdef _WIN32
#include <stdio.h>
#include <string.h>
#include "compat.h"

int x3c_optind = 1;
int x3c_optopt = 0;
char *x3c_optarg = NULL;
static int optpos = 1;

static int short_has_arg(const char *optstring, char c)
{
	const char *p = strchr(optstring, c);
	if (!p) return 0;
	return p[1] == ':';
}

static const x3c_option *find_long(const x3c_option *longopts,
				   const char *name, size_t len)
{
	const x3c_option *exact = NULL;
	size_t nmatch = 0;
	for (; longopts && longopts->name; longopts++) {
		if (strncmp(longopts->name, name, len) == 0) {
			if (longopts->name[len] == '\0')
				return longopts; /* 完全匹配 */
			exact = longopts;
			nmatch++;
		}
	}
	return (nmatch == 1) ? exact : NULL;
}

int x3c_getopt_long(int argc, char *const argv[], const char *optstring,
		    const x3c_option *longopts, int *longindex)
{
	const char *arg;

	if (x3c_optind >= argc) return -1;
	arg = argv[x3c_optind];

	if (optpos == 1 && arg[0] == '-' && arg[1] == '-') {
		/* 长选项 */
		const char *name = arg + 2;
		const char *eq = strchr(name, '=');
		size_t len = eq ? (size_t)(eq - name) : strlen(name);
		const x3c_option *o = find_long(longopts, name, len);

		if (!strcmp(name, "")) { x3c_optind++; return -1; } /* "--" 结束 */
		if (!o) {
			fprintf(stderr, "unrecognized option '--%s'\n", name);
			x3c_optind++;
			return '?';
		}
		if (longindex) *longindex = (int)(o - longopts);
		x3c_optind++;
		if (o->has_arg) {
			if (eq) {
				x3c_optarg = (char *)eq + 1;
			} else if (x3c_optind < argc) {
				x3c_optarg = argv[x3c_optind++];
			} else {
				fprintf(stderr, "option '--%s' requires an argument\n",
					o->name);
				x3c_optopt = o->val;
				return '?';
			}
		} else if (eq) {
			fprintf(stderr, "option '--%s' doesn't allow an argument\n",
				o->name);
			x3c_optopt = o->val;
			return '?';
		}
		optpos = 1;
		return o->val;
	}

	if (optpos == 1 && arg[0] == '-' && arg[1] != '\0') {
		/* 短选项(可能组合, 逐个返回) */
		char c = arg[optpos];
		optpos++;
		if (c == '\0') { x3c_optind++; optpos = 1; return -1; }
		if (!strchr(optstring, c)) {
			fprintf(stderr, "invalid option -- '%c'\n", c);
			x3c_optopt = c;
			x3c_optind++;
			optpos = 1;
			return '?';
		}
		x3c_optopt = c;
		if (short_has_arg(optstring, c)) {
			if (arg[optpos] != '\0') {
				x3c_optarg = (char *)arg + optpos;
				x3c_optind++;
				optpos = 1;
			} else if (x3c_optind + 1 < argc) {
				x3c_optarg = argv[x3c_optind + 1];
				x3c_optind += 2;
				optpos = 1;
			} else {
				fprintf(stderr, "option requires an argument -- '%c'\n", c);
				x3c_optind++;
				optpos = 1;
				return '?';
			}
			return c;
		}
		if (arg[optpos] == '\0') { x3c_optind++; optpos = 1; }
		return c;
	}

	optpos = 1;
	return -1;
}
#endif