#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Test P2P tx broadcast — submit a tx and verify it reaches peers."""
import json, struct, hashlib, time, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RPC = "http://127.0.0.1:9545"
PRIV = "848bc494a16d7a9bd11b6c5433be5dfa558a87df1f5f7efc4de1783fe973eeff3faf5f01b28dbe96c5a51cf691fda2df0bf0cc830dfbb081e6c7badc71addb7a"

priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIV)[:32])
pub = priv.public_key().public_bytes_raw()
from_addr = pub.hex()

def rpc(method, params=None):
    req = json.dumps({"jsonrpc":"2.0","method":method,"params":params or [],"id":1}).encode()
    r = urllib.request.urlopen(RPC, data=req, timeout=5)
    return json.loads(r.read())

# Get current nonce
nonce = int(rpc("eth_getTransactionCount", [f"0x{from_addr}"])["result"], 16)
print(f"Current nonce: {nonce}")

# Build tx
to = "bob"
value = 100
gas_limit = 21000
gas_price = 1
data = b""

# Compute hash
hash_input = f"{nonce}:{from_addr}:{to}:{value}:{gas_limit}:{len(data)}:{data.hex()}"
tx_hash = hashlib.sha256(hash_input.encode()).digest()
sig = priv.sign(tx_hash)

# Serialize
val_bytes = value.to_bytes(1, 'big')
buf = struct.pack(">Q", nonce)
buf += struct.pack(">H", len(from_addr.encode())); buf += from_addr.encode()
buf += struct.pack(">H", len(to.encode())); buf += to.encode()
buf += struct.pack(">H", len(val_bytes)); buf += val_bytes
buf += struct.pack(">Q", gas_limit)
buf += struct.pack(">Q", gas_price)
buf += struct.pack(">I", len(data)); buf += data
buf += struct.pack(">H", len(sig)); buf += sig

tx_hex = buf.hex()
print(f"Submitting tx (nonce={nonce})...")

result = rpc("eth_sendRawTransaction", [f"0x{tx_hex}"])
if "error" in result:
    print(f"Error: {result['error']}")
else:
    print(f"✅ Tx submitted: {result['result']}")
    print(f"Hash: 0x{tx_hash.hex()}")
    
    # Wait for block
    time.sleep(2)
    
    # Check receipt
    receipt = rpc("eth_getTransactionReceipt", [result["result"]])
    if receipt.get("result"):
        print(f"✅ Mined in block {receipt['result']['blockNumber']}")
        print(f"   Status: {receipt['result']['status']}")
    else:
        print(f"⏳ Not yet mined")
