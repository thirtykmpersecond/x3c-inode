#!/usr/bin/env python3
"""反解 H3C 802.1X Response-Identity 里的 28 字节 Base64 版本区。

用途：从能正常认证的客户端（如 iNode）抓包中，反解出服务器实际接受的版本串。
这是定位「上报版本号」的唯一可靠手段 —— 版本区含时间戳随机数，
每次运行 Base64 都不同，**不能直接比对字符串**。

算法（与 x3c.c 的 fill_client_version_area 互为逆运算）：
    1. Base64 解出 20 字节
    2. 用 H3C 密钥逆 XOR  -> clientarea
    3. 后 4 字节大端读出 random
    4. "%08x" % random 作密钥，逆 XOR 前 16 字节 -> 版本串

其中 XOR 是「先正向异或、再反向异或」，逆运算为「先反向、再正向」。

用法:
    python3 decode_version.py '<28字符Base64版本区>'
"""
import base64
import struct
import sys

KEY_NEW = b"Oly5D62FaE94W7"   # xorkey=1 新版密钥
KEY_OLD = b"HuaWei3COM1X"     # xorkey=0 老版密钥


def xor_fwd(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_rev(data, key):
    out = bytearray(data)
    i, j = len(data) - 1, 0
    while j < len(data):
        out[i] ^= key[j % len(key)]
        i -= 1
        j += 1
    return bytes(out)


def xor_inv(data, key):
    """XOR 的逆运算：先反向、再正向。"""
    return xor_fwd(xor_rev(data, key), key)


def decode(b64, key):
    area = base64.b64decode(b64)
    if len(area) != 20:
        raise ValueError(f"版本区应为 20 字节，实际 {len(area)}")
    clientarea = xor_inv(area, key)
    random = struct.unpack(">I", clientarea[16:20])[0]
    rk = ("%08x" % random).encode()
    version = xor_inv(clientarea[0:16], rk)
    return area, random, rk, version


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    b64 = sys.argv[1]
    for name, key in (("新版 Oly5D62FaE94W7 (-x 1)", KEY_NEW),
                      ("老版 HuaWei3COM1X (-x 0)", KEY_OLD)):
        try:
            area, random, rk, version = decode(b64, key)
        except Exception as e:
            print(f"--- {name} --- 解析失败: {e}")
            continue

        # 合理的版本串形如 "CH\x11V7.xx-yyyy" 或 "CH V3.60-6208"：
        # 前两字节为语言代码字母，第三字节是 0x11 或空格，且尾部补零
        ok = (version[0:2].isalpha()
              and version[2] in (0x11, 0x20)
              and all(32 <= b < 127 for b in version[3:].rstrip(b"\x00"))
              and version.rstrip(b"\x00") == version.replace(b"\x00", b""))
        print(f"--- key={name} ---")
        print(f"  20字节版本区 : {area.hex(' ')}")
        print(f"  random       : {random}  ->  rk = {rk.decode()}")
        print(f"  版本串 hex   : {version.hex(' ')}")
        print(f"  版本串       : {version.decode('latin1')!r}")
        print(f"  看起来合理?  : {'是' if ok else '否（说明密钥不对）'}")
        print()

    print("提示: 只有正确的密钥能解出干净 ASCII，可借此反证 -x 参数取值。")
    print("      若解出形如 'CH\\x11V7.xx-yyyy' 的可读字符串，即服务器接受的版本串。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
