# WayChain L1 — Agent Briefing

## Project Overview
WayChain is a Layer 1 blockchain built in Go with a custom EVM execution layer. It implements:
- **Consensus**: Custom BFT-style consensus with validator rotation
- **EVM**: Full bytecode interpreter with WayChain-native opcodes (0xF0-0xFF)
- **Precompiles**: 28 protocol precompiles at addresses 0x0C–0x27 (Oracle, Dox_Dev, BIJO, DMS, Bitcoin Registry, Storage Endowment, TwoWayVault, StabilityPool, TrustlessLock, AccountManager, Privacy, Governance, StateRent, CrossChainAttestation, MineralRights, Keccak256, 1WAY stablecoin, TaskRegistry, SWAY, SwapRoute, TemplateRegistry, GasFaucet)
- **Storage**: BoltDB (bbolt) persistent state with transaction indexing
- **RPC**: JSON-RPC over HTTP + WebSocket (eth_* + way_* methods)
- **P2P**: libp2p-based gossip for block/tx propagation

## Source of Truth (issue #23)
| Layer | Canonical | Not SoT |
|---|---|---|
| Protocol code | **this repo `master`** + `protocol-manifest.json` | monorepo `waychain/consensus`, chat, stale audits |
| Live deploy | **AWS 3.89.116.45** `/usr/local/bin/waychain` sha256 | "merged on GitHub" alone |
| Site | `ThinkIbrokeIt/waychain-site` `main` | master lag / monorepo site copy |
| Mobile | `ThinkIbrokeIt/waychain-mobile` `main` | unsigned ad-hoc builds |
| Work tracking | GitHub Issues + PRs | head memory |

`protocol-manifest.json` is generated from `evm/precompiles.go`. CI runs `scripts/audit-consistency.sh` on every PR. Drift = red.

**Address model (live-proven):** EOA account key / `tx.from` / `way_getBalance` = **full 64-hex** ed25519 pubkey. 20-byte form is **display only**. Precompile calldata address args = raw 20-byte. Selectors = `sha256(sig)[:4]` (not keccak). **0x21 = Keccak256** (SHA-3 hashing bridge; was briefly WIFRGantletRewards, corrected).

## Tech Stack
- **Language**: Go 1.26.4
- **ZK Circuits**: gnark (groth16) for balance/identity/range/membership proofs
- **Database**: go.etcd.io/bbolt v1.5.0
- **Crypto**: ed25519 signatures, sha256 hashing (NOT keccak256)
- **WebSocket**: nhooyr.io/websocket v1.8.17
- **Logging**: rs/zerolog v1.34.0

## Key Directories
```
/home/wink/projects/waychain-consensus/
├── chain.go                    # Core chain logic, block production, tx pool, staking
├── rpc.go                      # JSON-RPC server (HTTP + WS), eth_* + way_* methods
├── serialize.go                # Transaction serialization (RLP-style)
├── store/store.go              # BoltDB persistence (accounts, blocks, tx_index, meta)
├── evm/
│   ├── interpreter.go          # EVM bytecode interpreter + WayChain native opcodes
│   ├── precompiles.go          # 28 precompiles (0x0C–0x27) + ABI selectors
│   ├── governance.go           # Governance precompile (0x1D) + curator no-gatekeeping
│   ├── state_rent.go           # State rent calculation + payment
│   ├── oracle_scheduler.go     # Time-based oracle task scheduling
│   ├── cross_chain_attestation.go # Cross-chain attestation verification
│   ├── mineral_rights.go       # Mineral rights registry
│   ├── trustless_lock.go       # Trustless liquidity locks
│   ├── two_way.go              # Two-way peg vault
│   ├── stability_pool.go       # Stability pool for protocol
│   ├── account_manager.go      # Account management
│   ├── privacy.go              # Privacy precompile
│   ├── circuits/               # gnark ZK circuits (balance, identity, range, membership)
│   ├── *_test.go               # Unit tests for each precompile
├── go.mod / go.sum             # Dependencies
```

## Critical Conventions

### Address Format
- **EOA**: 20-byte hex string (lowercase, no 0x prefix in internal storage)
- **Precompiles**: `"000000000000000000000000000000000000%02x"` (e.g., 0x13 → 40-char hex)
- **Contracts**: SHA256(deployer + nonce)[:20] — NOT keccak256

### Lane Types (evm.LaneType)
```go
const (
    ConsensusLane LaneType = 0  // Standard public txs
    OracleLane    LaneType = 1  // Oracle attestation processing
    PrivateLane   LaneType = 2  // Encrypted private txs
)
```
Transaction.Lane determines which pool it enters and which EVM instance executes it.

### Dox_Dev Badge Levels (precompile 0x13)
- **Level 0**: Unverified (cannot deploy contracts)
- **Level 1**: Verified identity
- **Level 2**: Verified developer (can deploy Class B, apply for curator)
- **Level 3**: Curator (can issue badges, deploy Class A templates)

### Contract Classes
- **Class A (0)**: Template contracts from registry — anyone with Level 2+ can deploy (enforced by `CanDeployContract` in `evm/evm.go`)
- **Class B (1)**: Custom bytecode — requires Level 3 (curator) or governance approval (enforced by `EnforceContractClass` in `evm/evm.go`)
- Enforced in `EnforceContractClass(level, class)` and `CanDeployContract(level)`

### Precompile Addresses (0x0C–0x27)
| Addr | Name | Purpose |
|------|------|---------|
| 0x0C | OracleAggregator | Aggregate multi-oracle attestations |
| 0x0D | OracleScheduler | Schedule recurring oracle tasks |
| 0x0E | OracleVerifier | Verify single oracle attestation |
| 0x0F | TLSVerifier | Verify TLS notary proofs |
| 0x10 | AggregateSignatureVerify | ed25519 aggregate signature verification (chain identity scheme) |
| 0x11 | AccountRecovery | Guardian-based recovery (3-of-5) |
| 0x12 | StateRentCalc | Calculate rent due |
| 0x13 | DoxDevBadge | Identity/developer verification |
| 0x14 | BinaryJournal (BIJO) | Journal token (supply, transfers, governance) |
| 0x15 | DeadMansSwitch | Inactivity-triggered asset transfer |
| 0x16 | BitcoinRegistry | BTC address ↔ WayChain mapping |
| 0x17 | StorageEndowment | Perpetual storage funding |
| 0x18 | TwoWayVault | Two-way peg vault |
| 0x19 | StabilityPool | Protocol stability pool |
| 0x1A | TrustlessLock | Anti-rug liquidity locks |
| 0x1B | AccountManager | Account abstraction helpers |
| 0x1C | Privacy | Private transaction handling |
| 0x1D | Governance | Dox_Dev-weighted voting (Direct/Quadratic/Futarchy) |
| 0x1E | StateRent | Rent collection & eviction |
| 0x1F | CrossChainAttestation | Cross-chain proof verification |
| 0x20 | MineralRightsRegistry | Tokenized mineral rights |
| 0x21 | Keccak256 | SHA-3 hashing bridge (app-layer; was briefly WIFRGantletRewards) |
| 0x22 | WayStablecoin (1WAY) | Bitcoin-backed stablecoin: BTC locked → 1WAY minted |
| 0x23 | TaskRegistry | Decentralized task registry |
| 0x24 | SwayToken (SWAY) | DEX LP incentive token |
| 0x25 | SwapRoute | DEX swap + LP rewards |
| 0x26 | TemplateRegistry | Contract template registry |

### ABI Selectors
WayChain uses **sha256(signature)[:4]** NOT keccak256. All selectors in `precompiles.go` are precomputed constants.

### Storage Keys
All storage uses `sha256(data)` as 32-byte keys. Helper functions in `precompiles.go`:
- `storageKey(data)` — generic
- `addressKey(addr, prefix)` — address mappings
- `uint64Key(id, prefix)` — numeric mappings

## Common Commands

### Build & Test
```bash
cd /home/wink/projects/waychain-consensus
go build .                    # Builds 'waychain-consensus' binary
go test ./...                 # Run all tests (evm/*_test.go)
go test -v ./evm -run TestDoxDevBadge  # Run specific test
go vet ./...                  # Static analysis (may have false positives)
```

### Run Node
```bash
./waychain-consensus          # Starts RPC on :8545, P2P on :9000
# Or with persistent store:
./waychain-consensus -db /data/waychain.db
```

### RPC Endpoints
- HTTP: `http://localhost:9545` (local dev) or `https://api.waychain.org:8545` (via Cloudflare Tunnel)
- WS: `ws://localhost:9545/ws` (local dev) or `wss://api.waychain.org/ws` (via Cloudflare Tunnel)
- Custom methods: `way_getDoxLevel`, `way_getBalance`, `way_getBlockCount`

## Known Pitfalls & Gotchas

### 1. SHA256 vs Keccak256
**Everything uses SHA256** — contract addresses, storage keys, function selectors, tx hashes. Never use keccak256.

### 2. Precompile Address Encoding
Internal storage uses 40-char hex: `"0000000000000000000000000000000000000013"` for 0x13.
External RPC uses standard 0x-prefixed: `"0x0000000000000000000000000000000000000013"`.

### 3. Lane-Specific Execution
Transactions in OracleLane/PrivateLane execute with different EVM instances. State changes are shared but gas/precompile access may differ.

### 4. Dox_Dev Deploy Gates
- `CREATE`/`CREATE2` opcodes require Level 3 for Class B
- `DeployContractFromCode` (template deploy) requires Level 2+ for Class A
- Check `EnforceContractClass()` before deploying

### 5. BoltDB Concurrency
Store operations use `db.Update()` (write) and `db.View()` (read). Never hold transactions across goroutines. `SaveAllAccounts()` rewrites entire accounts bucket — call after each block.

### 6. Gas Accounting
- Precompiles return fixed gas cost (see `PrecompilesTable`)
- EVM opcodes use `OpcodeTable[op].Gas`
- Refunds capped at `gasUsed / 2`

### 7. Transaction Serialization
`serialize.go` uses custom format (not RLP):
```
[nonce:8][fromLen:1][from][toLen:1][to][value:32][gasLimit:8][gasPrice:8][dataLen:4][data][signatureLen:2][signature]
```
Use `Serialize()` / `DeserializeTxHex()` — don't hand-roll.

### 8. Go Version
Requires Go 1.26.4. `go vet` has false positives on gnark-generated code — use `go build .` as primary check.

### 9. Chain ID
WayChain uses **10008** (0x2718). Hardcoded in `rpc.go:142` and `chain.go:165`.

### 10. BIJO Token (0x14)
- Fixed supply: `BijoSupply` constant
- Transfers disabled by default (slot 1 = 0)
- Enable via governance: `enableTransfers()` selector
- 70% storage endowment, 10% airdrop, 20% ecosystem (per whitepaper)

### 11. Governance Voting (0x1D)
Three vote types with different thresholds:
- Direct: 50% quorum, 50% threshold
- Quadratic: uses voice credits (9/period), 60% threshold
- Futarchy: prediction markets, 66% threshold (for strategic decisions where outcome can be objectively measured)
Curator applications: any Level 2+ can apply; community elects via quadratic vote.

### 12. State Rent (0x1E)
- Charged per KB per block since last payment
- Non-payment → eviction (code/storage wiped)
- `StateRentCalc` precompile (0x12) estimates; `StateRent` precompile (0x1E) collects

### Critical Files to Read First
1. `chain.go` — Core loop, block production, tx pool, staking
2. `evm/interpreter.go` — Opcodes, precompile CALL handling, native ops
3. `evm/precompiles.go` — All 28 precompiles, selectors, storage helpers
4. `evm/governance.go` — Governance logic, curator no-gatekeeping
5. `rpc.go` — JSON-RPC methods, tx submission, P2P broadcast (eth_sendRawTransaction, eth_getTransactionByHash, eth_getTransactionReceipt now fixed)
6. `store/store.go` — Persistence, serialization, tx indexing (transaction data now persistently stored)

## Whitepaper Truth Table Protocol
**Before claiming any feature is "live": verify on-chain.**
- Spec'd ≠ Built ≠ Live
- Enum in code ≠ Feature works
- Reserved precompile ≠ Implemented
- Build truth table: Claim → Evidence (tx hash, block, code path) → Status (✅/⚠️/❌)

## Design Tokens (WayChain Brand)
- Background: #0A0A0F (very dark slate)
- Body text: #C8D0D9 (silver-grey), 18px fixed, line-height 1.8 (2.0 mobile)
- Max-width: 700px centered
- Headlines/links: #00B4FF (electric blue) — NEVER body text
- Accent: #B87333 (copper), #FFBF00 (amber)
- Fonts: System only (no Courier New)
- Logo: Wardenclyffe Lighthouse
- Gold/Silver: Always troy oz

## Partnership Protocol (OWL + Wink)
- Load relevant profile for task (10 profiles available)
- Check kanban: `hermes kanban list`
- Cross-profile work → create kanban card with correct assignee
- Kanban = shared brain, handoff mechanism
- Verify on-chain before claiming done

## Key Project Documents
- `/home/wink/projects/WAYCHAIN_REAL_PLAN.md`: The actionable plan for getting WayChain to "real" status.
- `/home/wink/projects/NEW_CHAIN_TOKENOMICS.md`: Detailed specification of WayChain's token economic model.
- `/home/wink/projects/NEW_CHAIN_CROSS_CHAIN_ATTESTATIONS.md`: Specification for cross-chain attestation and oracle functionality.

## Session Startup Checklist
1. Read this AGENTS.md
2. Check git status: `git status`
3. Check kanban: `hermes kanban list`
4. Verify chain builds: `go build .`
5. Run tests if modifying precompiles/EVM: `go test ./evm/...`