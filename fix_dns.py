#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import json, os, sys

# Read token from file
with open(os.path.expanduser("~/.cloudflared/cf_token")) as f:
    token = f.read()...ne = "81c3904fbece40de8e8130bcbe9e1db4"
rec_id = "6d13bcc2006989c85e5f53439a42c2d0"
new_url = "restructuring-shirt-grey-intervention.trycloudflare.com"

# Update DNS
import urllib.request
req = urllib.request.Request(
    f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec_id}",
    data=json.dumps({"content": new_url, "proxied": False}).encode(),
    headers={
        "Authorization": f"Bearer ***       "Content-Type": "application/json",
    },
    method="PATCH"
)
resp = urllib.request.urlopen(req, timeout=15)
d = json.loads(resp.read())
if d.get("success"):
    print("✅ DNS updated")
else:
    print(f"❌ Error: {d.get('errors')}")

# Test tunnel
req2 = urllib.request.Request(
    f"https://{new_url}/",
    data=json.dumps({"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
resp2 = urllib.request.urlopen(req2, timeout=10)
print(f"Tunnel: {json.loads(resp2.read())}")
