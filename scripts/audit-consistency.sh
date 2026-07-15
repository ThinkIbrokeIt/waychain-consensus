#!/usr/bin/env bash
# WayChain consistency audit — PR + daily CI.
# Fails hard on precompile / address-model / banner drift.
# Parent issue: #23  Child: #24
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Audit: protocol-manifest ==="
python3 scripts/gen-protocol-manifest.py --check

echo "=== Audit: precompile count (code vs AGENTS.md vs manifest) ==="
CODE_COUNT=$(grep -oE '^\s*0x[0-9a-fA-F]{2}: \{' evm/precompiles.go | wc -l | tr -d ' ')
MANIFEST_COUNT=$(python3 -c "import json; print(json.load(open('protocol-manifest.json'))['precompile_count'])")
echo "Code registers: $CODE_COUNT"
echo "Manifest:       $MANIFEST_COUNT"

DOC_LINE=$(grep -oE '[0-9]+ protocol precompiles at addresses 0x0C' AGENTS.md | grep -oE '^[0-9]+' | head -1 || true)
if [ -z "$DOC_LINE" ]; then
  DOC_LINE=$(grep -oE 'All [0-9]+ precompiles' AGENTS.md | grep -oE '[0-9]+' | head -1 || true)
fi
echo "AGENTS.md:      ${DOC_LINE:-UNKNOWN}"

if [ -z "${DOC_LINE:-}" ]; then
  echo "::error::Could not parse precompile count from AGENTS.md"
  exit 1
fi
if [ "$CODE_COUNT" != "$DOC_LINE" ] || [ "$CODE_COUNT" != "$MANIFEST_COUNT" ]; then
  echo "::error::Precompile count drift — code=$CODE_COUNT AGENTS.md=$DOC_LINE manifest=$MANIFEST_COUNT"
  exit 1
fi
if [ "$CODE_COUNT" != "27" ]; then
  echo "::error::Unexpected precompile count $CODE_COUNT (expect 27 for 0x0C-0x26)"
  exit 1
fi

echo "=== Audit: IsPrecompile range ==="
if ! grep -qE 'addr >= 0x0C && addr <= 0x26' evm/precompiles.go; then
  echo "::error::IsPrecompile range is not 0x0C..0x26"
  exit 1
fi

echo "=== Audit: PrecompileNames banner + loop (must include 0x26) ==="
if grep -q 'WayChain Precompiles (0x0C-0x20)' evm/precompiles.go; then
  echo "::error::PrecompileNames still claims 0x0C-0x20 (stale). Must be 0x0C-0x26."
  exit 1
fi
if ! grep -q 'WayChain Precompiles (0x0C-0x26)' evm/precompiles.go; then
  echo "::error::PrecompileNames missing 0x0C-0x26 banner"
  exit 1
fi
if ! grep -qE 'for addr := byte\(0x0C\); addr <= 0x26; addr\+\+' evm/precompiles.go; then
  echo "::error::PrecompileNames loop must iterate addr <= 0x26"
  exit 1
fi

echo "=== Audit: 0x21 is WIFR (not Keccak) ==="
# Name in table for 0x21 must be WIFRGantletRewards
if ! python3 - <<'PY'
import json,re,sys
m=json.load(open('protocol-manifest.json'))
e=next(x for x in m['precompiles'] if x['addr']=='0x21')
if e['name']!='WIFRGantletRewards':
    print('::error::0x21 name is %r, expected WIFRGantletRewards'%e['name']); sys.exit(1)
src=open('evm/precompiles.go').read()
# reject false Keccak claim next to 0x21 table entry region
if re.search(r'0x21:[\s\S]{0,200}Keccak', src):
    print('::error::0x21 block mentions Keccak in precompiles.go'); sys.exit(1)
print('0x21 =', e['name'])
PY
then
  exit 1
fi

echo "=== Audit: AGENTS must not claim Keccak at 0x21 ==="
# Allow explicit denials ("not Keccak256" / "≠ Keccak") — only fail positive claims.
# (Do NOT wrap in `if cmd; then exit 1` — that inverts set -e.)
python3 - <<'PY'
import re, sys
text = open('AGENTS.md').read().splitlines()
bad = []
for i, l in enumerate(text, 1):
    if not re.search(r'0x21', l, re.I):
        continue
    if not re.search(r'Keccak', l, re.I):
        continue
    if re.search(r'not\s+Keccak|≠\s*Keccak|!=\s*Keccak|isn.?t\s+Keccak|no longer\s+Keccak', l, re.I):
        continue
    bad.append(f'{i}:{l.strip()[:160]}')
if bad:
    print('::error::AGENTS.md positively claims Keccak at 0x21:')
    print('\n'.join(bad))
    sys.exit(1)
print('AGENTS.md: no positive Keccak@0x21 claim')
PY

echo "✅ Consistency audit passed (count=$CODE_COUNT, range=0x0C-0x26)"
exit 0
