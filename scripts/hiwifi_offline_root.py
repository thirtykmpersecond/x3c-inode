#!/usr/bin/env python3
"""极路由离线开启 SSH 22 端口（无需云端）。

原理：/local-ssh 调试接口的 cloud_token 由 local_token + uuid 本地计算。
用法：python3 hiwifi_offline_root.py [router_ip]
成功后 5 分钟内 ssh root@<ip>（密码=后台管理密码）。
"""
import base64, hashlib, hmac, json, subprocess, sys, time

BASE = "http://" + (sys.argv[1] if len(sys.argv) > 1 else "192.168.199.1")


def curl(url):
    return subprocess.run(["curl", "-s", "-m", "15", url], capture_output=True, text=True).stdout


def get_local_token():
    return json.loads(curl(BASE + "/local-ssh/api?method=get"))["data"]


def get_uuid():
    return json.loads(curl(BASE + "/cgi-bin/turbo/proxy/router_info"))["data"]["uuid"]


def compute_cloud_token(local_token, uuid):
    decoded = base64.b64decode(local_token)
    parts = decoded.split(b",")
    parts[2] = str(int(parts[2]) + 1).encode()
    msg = b",".join(parts[:3])
    key = hashlib.sha1(uuid.encode()).digest()
    return base64.b64encode(hmac.new(key, msg, hashlib.sha1).digest()).decode()


def main():
    uuid = get_uuid()
    print(f"uuid={uuid}")
    for attempt in range(12):
        local_token = get_local_token()
        cloud_token = compute_cloud_token(local_token, uuid)
        url = BASE + "/local-ssh/api?method=valid&data=" + cloud_token.replace("+", "%2B")
        resp = curl(url)
        print(f"[{attempt}] -> {resp}")
        if "Success" in resp or "port is" in resp:
            print(f"SSH 已开启：ssh -o HostKeyAlgorithms=+ssh-rsa root@{BASE.split('//')[1]}")
            return
        time.sleep(2)
    print("未成功，请检查 local_token 是否返回或重试")


if __name__ == "__main__":
    main()