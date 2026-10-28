# x3c8021x 重写版 Makefile (Linux/macOS/Windows 交叉编译)
#
# 本机编译(Linux):            make
# macOS:                     make
# Windows (MinGW 交叉编译):   make CC=x86_64-w64-mingw32-gcc LIBS="-lwpcap -liphlpapi -lws2_32"
#                            (需安装 Npcap SDK 并设置 NPCAP_DIR)
# 本机编译需 libpcap 头文件:  sudo apt-get install libpcap-dev

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
NPCAP_DIR ?= /usr/local/npcap-sdk

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

# MinGW 即使 -o 指定无后缀名, 输出也会被自动加上 .exe
EXE :=
ifeq ($(OS),Windows_NT)
  EXE := .exe
endif
ifneq (,$(findstring mingw,$(CC)))
  EXE := .exe
endif
APP     := x3c8021x-re$(EXE)

ifeq ($(OS),Windows_NT)
  LIBS := -lwpcap -liphlpapi -lws2_32
else
  LIBS := -lpcap
endif

ifneq ($(wildcard $(NPCAP_DIR)/Include),)
  CFLAGS += -I$(NPCAP_DIR)/Include
  LIBS   += -L$(NPCAP_DIR)/Lib/x64
endif

SRCS := x3c.c dev.c md5.c compat.c ipv6.c
OBJS := $(SRCS:.c=.o)

all: $(APP)

$(APP): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

x3c.o: x3c.c x3c.h ipv6.h compat.h
ipv6.o: ipv6.c ipv6.h
dev.o: dev.c x3c.h compat.h
md5.o: md5.c x3c.h
compat.o: compat.c compat.h

clean:
	rm -f $(OBJS) $(APP) *.exe

.PHONY: all clean