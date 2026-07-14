#!/usr/bin/env bash
# WayChain consistency audit — runs in CI on a schedule.
# Fails (non-zero) if code and docs disagree on precompile count.
# Drift like "AGENTS.md says 20 precompiles, code has 27" is exactly
# what this catches so it never sits stale in someone's head again.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Audit: precompile count (code vs AGENTS.md) ==="

# Count real registered precompiles in PrecompilesTable (0xNN: { entries).
CODE_COUNT=$(grep -oE '^\s*0x[0-9a-fA-F]{2}: \{' evm/precompiles.go | wc -l | tr -d ' ')
echo "Code registers: $CODE_COUNT precompiles"

# What does AGENTS.md claim?
DOC_LINE=$(grep -oE '[0-9]+ protocol precompiles at addresses 0x0C' AGENTS.md | grep -oE '^[0-9]+' | head -1 || true)
if [ -z "$DOC_LINE" ]; then
  # fall back: look for "All N precompiles" style
  DOC_LINE=$(grep -oE 'All [0-9]+ precompiles' AGENTS.md | grep -oE '[0-9]+' | head -1 || true)
fi
echo "AGENTS.md claims: ${DOC_LINE:-UNKNOWN} precompiles"

if [ -z "$DOC_LINE" ]; then
  echo "::error::Could not parse precompile count from AGENTS.md"
  exit 1
fi

if [ "$CODE_COUNT" != "$DOC_LINE" ]; then
  echo "::error::Precompile count drift — code=$CODE_COUNT AGENTS.md=$DOC_LINE"
  exit 1
fi

echo "✅ Precompile count consistent ($CODE_COUNT)"
exit 0
