import base64, hashlib, hmac, json, urllib.request, urllib.parse, sys

BASE = "http://192.168.199.1"

def get_local_token():
    req = urllib.request.Request(BASE + "/local-ssh/api?method=get")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())["data"]

def get_uuid():
    req = urllib.request.Request(BASE + "/cgi-bin/turbo/proxy/router_info")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())["data"]["uuid"]

def compute_cloud_token(local_token, uuid):
    decoded = base64.b64decode(local_token)
    parts = decoded.split(b",")
    timestamp = int(parts[2]) + 1
    parts[2] = str(timestamp).encode()
    msg = b",".join(parts[:3])
    key = hashlib.sha1(uuid.encode()).digest()
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    return base64.b64encode(mac).decode()

def valid_cloud_token(cloud_token):
    data = urllib.parse.quote(cloud_token, safe="")
    req = urllib.request.Request(BASE + "/local-ssh/api?method=valid&data=" + data)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

if __name__ == "__main__":
    uuid = get_uuid()
    local_token = get_local_token()
    print("uuid:", uuid)
    print("local_token:", local_token)
    cloud_token = compute_cloud_token(local_token, uuid)
    print("cloud_token:", cloud_token)
    resp = valid_cloud_token(cloud_token)
    print("valid resp:", json.dumps(resp, ensure_ascii=False))