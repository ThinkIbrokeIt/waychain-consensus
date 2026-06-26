#!/usr/bin/env python3
import json, subprocess, os, sys

# Read token from file
with open("/home/wink/.cloudflared/cf_token") as f:
    TOKEN = f.read().strip()

ZONE_ID = "81c3904fbece40de8e8130bcbe9e1db4"

def cf(method, path, data=None):
    cmd = [
        "curl", "-s", "-X", method,
        f"https://api.cloudflare.com/client/v4/{path}",
        "-H", f"Authorization: Bearer {TOKEN}",
        "-H", "Content-Type: application/json"
    ]
    if data:
        cmd += ["-d", json.dumps(data)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return json.loads(r.stdout)

# Step 1: Get account ID
zone = cf("GET", f"zones/{ZONE_ID}")
if not zone.get("success"):
    print(f"FAIL: can't get zone: {zone.get('errors')}")
    sys.exit(1)
aid = zone["result"]["account"]["id"]
print(f"Account: {aid}")

# Step 2: Create tunnel
tun = cf("POST", f"accounts/{aid}/cfd_tunnel", {
    "name": "waychain-rpc", "config_src": "cloudflared"
})
if not tun.get("success"):
    print(f"FAIL: tunnel create: {tun.get('errors')}")
    sys.exit(1)

tid = tun["result"]["id"]
tun_token = tun["result"].get("token", "")
print(f"Tunnel: {tid}")

# Step 3: Route DNS
route = cf("PUT", f"accounts/{aid}/cfd_tunnel/{tid}/dns?name=api.waychain.org&type=CNAME")
if route.get("success"):
    print(f"DNS: api.waychain.org -> tunnel")
else:
    # Might already exist, try adding a DNS record directly
    print(f"DNS route warn: {route.get('errors')}")
    # Set up CNAME for api.waychain.org
    dns = cf("POST", f"zones/{ZONE_ID}/dns_records", {
        "type": "CNAME", "name": "api",
        "content": f"{tid}.cfargotunnel.com",
        "ttl": 120, "proxied": True
    })
    if dns.get("success"):
        print(f"DNS: api.waychain.org -> {tid}.cfargotunnel.com")
    else:
        print(f"DNS: {dns.get('errors')}")

# Step 4: Save credentials
creds = {
    "AccountTag": aid, "TunnelID": tid,
    "TunnelName": "waychain-rpc", "Token": tun_token
}
with open("/home/wink/.cloudflared/waychain-rpc.json", "w") as f:
    json.dump(creds, f)

# Step 5: Create config
config = {
    "tunnel": tid,
    "credentials-file": "/home/wink/.cloudflared/waychain-rpc.json",
    "ingress": [
        {"hostname": "api.waychain.org", "service": "http://localhost:9545"},
        {"service": "http_status:404"}
    ]
}
with open("/home/wink/.cloudflared/waychain-rpc-config.yml", "w") as f:
    # Simple YAML-like format
    f.write(f"tunnel: {tid}\n")
    f.write(f"credentials-file: /home/wink/.cloudflared/waychain-rpc.json\n")
    f.write("ingress:\n")
    f.write("  - hostname: api.waychain.org\n")
    f.write("    service: http://localhost:9545\n")
    f.write("  - service: http_status:404\n")

print("Config saved")
print()
print(f"To start the tunnel:")
print(f"  cloudflared tunnel --config /home/wink/.cloudflared/waychain-rpc-config.yml run")
