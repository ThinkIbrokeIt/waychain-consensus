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
if [ "$CODE_COUNT" != "28" ]; then
  echo "::error::Unexpected precompile count $CODE_COUNT (expect 28 for 0x0C-0x27)"
  exit 1
fi

echo "=== Audit: IsPrecompile range ==="
if ! grep -qE 'addr >= 0x0C && addr <= 0x27' evm/precompiles.go; then
  echo "::error::IsPrecompile range is not 0x0C..0x27"
  exit 1
fi

echo "=== Audit: PrecompileNames banner + loop (must include 0x27) ==="
if grep -q 'WayChain Precompiles (0x0C-0x20)' evm/precompiles.go; then
  echo "::error::PrecompileNames still claims 0x0C-0x20 (stale). Must be 0x0C-0x27."
  exit 1
fi
if ! grep -q 'WayChain Precompiles (0x0C-0x27)' evm/precompiles.go; then
  echo "::error::PrecompileNames missing 0x0C-0x27 banner"
  exit 1
fi
if ! grep -qE 'for addr := byte\(0x0C\); addr <= 0x27; addr\+\+' evm/precompiles.go; then
  echo "::error::PrecompileNames loop must iterate addr <= 0x27"
  exit 1
fi

echo "=== Audit: 0x21 is Keccak256 (app-layer hashing bridge) ==="
# Live code (root AGENTS.md, usestrix-aligned): 0x21 = Keccak256.
if ! python3 - <<'PY'
import json,re,sys
m=json.load(open('protocol-manifest.json'))
e=next(x for x in m['precompiles'] if x['addr']=='0x21')
if e['name']!='Keccak256':
    print('::error::0x21 name is %r, expected Keccak256'%e['name']); sys.exit(1)
src=open('evm/precompiles.go').read()
if re.search(r'0x21:[\s\S]{0,200}WIFRGantlet', src):
    print('::error::0x21 block still claims WIFRGantletRewards in precompiles.go'); sys.exit(1)
print('0x21 =', e['name'])
PY
then
  exit 1
fi

echo "=== Audit: AGENTS must not claim WIFR@0x21 (it is Keccak256) ==="
# Only fail on a POSITIVE assignment (table row "| 0x21 | WIFRGantletRewards |").
# Historical mentions ("was WIFRGantletRewards") are legitimate context.
python3 - <<'PY'
import re, sys
text = open('AGENTS.md').read().splitlines()
bad = []
for i, l in enumerate(text, 1):
    if not re.search(r'0x21', l, re.I):
        continue
    # positive table assignment: | 0x21 | WIFRGantlet... |
    if re.search(r'\|\s*0x21\s*\|\s*WIFRGantlet', l, re.I):
        bad.append(f'{i}:{l.strip()[:160]}')
if bad:
    print('::error::AGENTS.md positively assigns WIFRGantlet@0x21 (should be Keccak256):')
    print('\n'.join(bad))
    sys.exit(1)
print('AGENTS.md: no positive WIFRGantlet@0x21 assignment')
PY

echo "=== Audit: ROOT AGENTS.md + REPO_LAW.md must match 28 @ 0x0C-0x27 (single source of truth) ==="
ROOT_AGENTS="../AGENTS.md"
REPO_LAW="../REPO_LAW.md"
for f in "$ROOT_AGENTS" "$REPO_LAW"; do
  if [ ! -f "$f" ]; then
    echo "::warning:: $f not found (skipping root-doc drift check)"
    continue
  fi
  body=$(cat "$f")
  # reject stale '27 @ 0x0C-0x26' / '27 @ 0x0C–0x26' (hyphen or en-dash) / '27 precompiles'
  if echo "$body" | grep -qE '27[^0-9][^@]*0x0C[-–]0x26' \
     || echo "$body" | grep -qiE '\b27 (native )?precompiles\b'; then
    echo "::error::$f still claims stale '27 @ 0x0C-0x26' / 27 precompiles. Must be 28 @ 0x0C-0x27."
    exit 1
  fi
  # require correct count
  if ! echo "$body" | grep -qE '28[^0-9].*0x0C[-–]0x27' \
     && ! echo "$body" | grep -qiE '\b28 (native )?precompiles\b'; then
    echo "::error::$f does not state '28 @ 0x0C-0x27' / '28 precompiles'. Update it."
    exit 1
  fi
  echo "✅ $(basename "$f") matches 28 @ 0x0C-0x27"
done

echo "✅ Consistency audit passed (count=$CODE_COUNT, range=0x0C-0x27)"
exit 0
