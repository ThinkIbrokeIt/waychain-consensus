// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ════════════════════════════════════════════════════════════════════════
// Economic Health Engine — on-chain macroeconomics for WayChain
//
// The "economic health model" spec describes a Solidity analytics contract
// fed by oracles that adjusts protocol variables by economic phase. On
// WayChain the SOURCE OF TRUTH is the Go core (TaskRegistry 0x23 pays WAY,
// sha256 is core hashing). This file implements the four decentralized
// indicators + the phase-driven feedback loop NATIVELY, so the numbers are
// computed by the chain itself — not reconstructed off-chain.
//
//   Oracle / IPFS ──► [Analytics (this file)] ──► [Dynamic Protocol Variables]
//
// The Solidity EconoAnalytics.sol in contracts/ is the APP-LAYER mirror: an
// EconoOracle replays this Go-computed snapshot so dapps can read it via
// standard EVM calls. The Go core never trusts the mirror; the mirror trusts
// the core. (Doctrine: one voice per layer.)
//
// Bounded by hard caps so governance/loop can never hyperinflate or zero-out
// the token (same discipline as inflation.go's 3%–9% window).
// ════════════════════════════════════════════════════════════════════════

const (
	// EconoWindowBlocks: rolling window for GBP / velocity = one epoch.
	EconoWindowBlocks uint64 = 10_000

	// Expansion thresholds (tunable, but bounded).
	// High GBP = at least 0.1% of the 100M starting WAY paid in-window.
	EconoGBPExpansionThreshold uint64 = 100_000
	// High velocity = at least 1% of circulating WAY changing hands/window.
	EconoVelocityExpansionThreshold uint64 = 100 // basis points

	// MRT (mineral-rights claim) WEIGHT — a verified claim is a HUGE factor
	// and is treated as a PRIMARY expansion signal. Each verified claim is
	// real-world asset acquisition on-chain: the strongest evidence of genuine,
	// tangible-backed economic output. We weight its token supply heavily into
	// GBP-equivalent output AND let the verified-claim RATE itself push the
	// economy toward Expansion. No dampening: MRT is the anchor of the model.
	EconoMRTPayWeight uint64 = 1_000
	// A cluster of verified claims in-window is itself an expansion signal.
	EconoMRTExpansionClaims uint64 = 10 // >= this many verified claims/window => Expansion pull

	// Dynamic-variable hard caps (so the loop can never blow up the token).
	EconoMaxBurnBps    uint64 = 500 // max 5% of treasury burned in expansion
	EconoMaxGrantBps   uint64 = 500 // max 5% of treasury granted in consolidation
	EconoExpansionBurnBps  uint64 = 50  // 0.5% treasury burn during expansion
	EconoConsolidationGrantBps uint64 = 200 // 2.0% treasury stimulus during consolidation
)

// EconoSnapshot is the rolling-window accumulator (single node, package-scoped
// like activeInflationPct in inflation.go). Reset each epoch by AccrueEcono.
type EconoSnapshot struct {
	GBP           uint64 // total WAY paid for completed tasks this window
	Tasks         uint64 // total completed tasks this window (token handoffs)
	ProPaid       uint64 // WAY paid for professional (high-tier) tasks
	ProTasks      uint64 // count of professional tasks
	MicroPaid     uint64 // WAY paid for micro tasks
	MicroTasks    uint64 // count of micro tasks
	MRTPaid       uint64 // GBP-equivalent weight of verified MRT claims this window
	MRTClaims     uint64 // count of verified MRT claims this window
	RentPaid      uint64 // WAY paid in state rent this window (recurring output)
	StorageStaked uint64 // WAY staked into StorageEndowment (data-storage economy)
	WindowStart   uint64 // block the window opened
	Phase         uint8  // 0 Consolidation, 1 Expansion (last computed)
}

// econoSnap holds the live accumulator. Per-epoch reset keeps it bounded.
var econoSnap = EconoSnapshot{WindowStart: 0, Phase: 0}

// EconoAccruePayout records a single completed-task payout into the rolling
// window. Called from task_registry.verifyAndPay on every actual WAY transfer.
// isPro distinguishes professional (high-tier, licensed) from micro tasks — the
// basis for the Task Yield Spread indicator.
func EconoAccruePayout(amount uint64, isPro bool, blockNum uint64) {
	// Reset the window if we've crossed into a new epoch.
	if blockNum-econoSnap.WindowStart >= EconoWindowBlocks {
		econoSnap = EconoSnapshot{WindowStart: blockNum}
	}
	econoSnap.GBP += amount
	econoSnap.Tasks++
	if isPro {
		econoSnap.ProPaid += amount
		econoSnap.ProTasks++
	} else {
		econoSnap.MicroPaid += amount
		econoSnap.MicroTasks++
	}
}

// EconoAccrueMRT records a verified mineral-rights claim — a HUGE factor.
// tokenSupply is the claim's on-chain token supply; it is weighted heavily
// (EconoMRTPayWeight) into GBP-equivalent economic output. Verified claims are
// also counted as professional-class output (real-asset acquisition requires
// lawyer + surveyor verification) so they lift the yield spread + employment.
func EconoAccrueMRT(tokenSupply uint64, blockNum uint64) {
	if blockNum-econoSnap.WindowStart >= EconoWindowBlocks {
		econoSnap = EconoSnapshot{WindowStart: blockNum}
	}
	weighted := tokenSupply * EconoMRTPayWeight
	econoSnap.MRTPaid += weighted
	econoSnap.MRTClaims++
	// Real-asset acquisition also counts as a professional (skilled) output:
	// it requires a lawyer + surveyor (Dox_Dev L2+) to verify.
	econoSnap.ProPaid += weighted
	econoSnap.ProTasks++
	econoSnap.Tasks++
}

// EconoAccrueRent records a state-rent payment — recurring economic output.
// Rent is paid by accounts to keep their state alive; it is a steady, real
// stream of chain revenue and counts directly as GBP-equivalent output and as
// a token handoff (velocity). It is NOT weighted (already real WAY).
func EconoAccrueRent(amount uint64, blockNum uint64) {
	if blockNum-econoSnap.WindowStart >= EconoWindowBlocks {
		econoSnap = EconoSnapshot{WindowStart: blockNum}
	}
	econoSnap.RentPaid += amount
	econoSnap.Tasks++ // a rent payment is token changing hands
}

// EconoAccrueStorage records a StorageEndowment operator stake — the data-
// storage economy. Capital committed to run the chain's persistent storage is a
// real, tangible economic commitment (like MRT it is committed capital, not
// churn). Weighted as a primary output signal.
func EconoAccrueStorage(amount uint64, blockNum uint64) {
	if blockNum-econoSnap.WindowStart >= EconoWindowBlocks {
		econoSnap = EconoSnapshot{WindowStart: blockNum}
	}
	econoSnap.StorageStaked += amount
	econoSnap.Tasks++
}

// EconoPolicy is the live dynamic-variable state the loop drives.
type EconoPolicy struct {
	Phase    uint8
	BurnBps  uint64 // treasury burn rate applied during expansion
	GrantBps uint64 // treasury stimulus rate applied during consolidation
}

// econoPolicy holds the live dynamic variables (read by RPC + state rent).
var econoPolicy = EconoPolicy{Phase: 0, BurnBps: 0, GrantBps: 0}

// AccrueEcono is called by the consensus engine at each epoch rollover. It
// freezes the window, computes the phase, and stores it. The actual per-payout
// accrual happens in EconoAccruePayout; this finalizes the phase for the loop.
func AccrueEcono(s *StateDB, blockNum uint64) {
	econoSnap.Phase = ComputeEconoPhase(s, blockNum)
}

// EconoGBPEquiv returns the GBP-equivalent economic output this window:
// raw task payouts + state rent (recurring) + heavily-weighted MRT real-asset
// acquisition + StorageEndowment capital committed. MRT and storage are HUGE
// factors, summed in (not buried) — they are the tangible backbone of the
// chain's economic output. Rent is real recurring revenue; included at face.
func EconoGBPEquiv() uint64 {
	return econoSnap.GBP + econoSnap.RentPaid + econoSnap.MRTPaid + econoSnap.StorageStaked
}

// ComputeEconoPhase returns 1 (Expansion) when the economy shows genuine
// expansion signals. Per the spec: "During Expansion (High GBP, High Velocity)".
// MRT (verified real-asset claims) is a PRIMARY signal — a cluster of verified
// claims in-window is itself an expansion pull, on top of the GBP+velocity test.
// This is deliberate: real-world asset acquisition on-chain is the strongest
// evidence the economy is growing, not just tokens churning.
func ComputeEconoPhase(s *StateDB, blockNum uint64) uint8 {
	highOutput := EconoGBPEquiv() >= EconoGBPExpansionThreshold
	highVelocity := EconoVelocityBps(s) >= EconoVelocityExpansionThreshold
	mrtSurge := econoSnap.MRTClaims >= EconoMRTExpansionClaims
	// Expansion when output+velocity are high, OR when real-asset acquisition
	// is surging (MRT alone can pull the chain into Expansion — it is huge).
	if (highOutput && highVelocity) || mrtSurge {
		return 1
	}
	return 0
}

// EconoVelocityBps returns token velocity in basis points:
//   tasks (token handoffs) / circulating WAY supply, * 10000.
func EconoVelocityBps(s *StateDB) uint64 {
	supply := QuestTotalSupply(s)
	if supply.Sign() == 0 {
		return 0
	}
	return econoSnap.Tasks * 10_000 / supply.Uint64()
}

// EconoEmploymentBps returns network employment in basis points:
//   active task-takers / total addresses, * 10000.
// Active task-taker = an address that holds a verified task slot (byte[31]==2)
// under the 0x23 per-claimant storage key sha256(0x10 || addr). The
// denominator is the total non-empty addresses in state.
func EconoEmploymentBps(s *StateDB) uint64 {
	total := 0
	active := 0
	for addr, acc := range s.Accounts {
		if acc == nil {
			continue
		}
		if (acc.Balance != nil && acc.Balance.Sign() > 0) || len(acc.Code) > 0 {
			total++
		}
		// Compute the exact verified-task slot key for this account and check
		// its value (byte[31]==2 means verified). The key is a sha256 digest,
		// so we must derive it — we cannot scan for a 0x10 prefix byte.
		claimKey := storageKey(append([]byte{0x10}, []byte(addr)...))
		if v := acc.Storage[claimKey]; v[31] == 2 {
			active++
		}
	}
	if total == 0 {
		return 0
	}
	return uint64(active) * 10_000 / uint64(total)
}

// EconoYieldSpreadBps returns the Task Yield Spread in basis points:
//   avg professional payout / avg micro payout, * 10000.
// 10000 (1.0) means skilled and micro pay the same; >10000 = skilled premium.
func EconoYieldSpreadBps() uint64 {
	var microAvg, proAvg uint64
	if econoSnap.MicroTasks > 0 {
		microAvg = econoSnap.MicroPaid / econoSnap.MicroTasks
	}
	if econoSnap.ProTasks > 0 {
		proAvg = econoSnap.ProPaid / econoSnap.ProTasks
	}
	if microAvg == 0 {
		return 0
	}
	return proAvg * 10_000 / microAvg
}

// GetEconoIndicators returns the four indicators + phase for RPC / oracle.
// MRT (real-asset acquisition) is surfaced as a first-class field — a HUGE
// factor the dashboard and oracle must show prominently, not hide.
func GetEconoIndicators(s *StateDB, blockNum uint64) map[string]interface{} {
	return map[string]interface{}{
		"grossBlockchainProduct": econoSnap.GBP,
		"gdpEquivalent":          EconoGBPEquiv(), // tasks + rent + weighted MRT + storage
		"mrtPaidWeighted":        econoSnap.MRTPaid,
		"mrtClaimsVerified":      econoSnap.MRTClaims,
		"rentPaid":               econoSnap.RentPaid,
		"storageStaked":          econoSnap.StorageStaked,
		"employmentBps":          EconoEmploymentBps(s),
		"velocityBps":            EconoVelocityBps(s),
		"yieldSpreadBps":         EconoYieldSpreadBps(),
		"phase":                  econoSnap.Phase,
		"phaseLabel":             phaseName(econoSnap.Phase),
		"windowBlocks":           EconoWindowBlocks,
		"windowStart":            econoSnap.WindowStart,
	}
}

// ApplyEconoPolicy runs the automated feedback loop. Called by the consensus
// engine at each epoch rollover AFTER AccrueEcono. It adjusts the dynamic
// protocol variables by phase, hard-capped so the token cannot be destabilized:
//   Expansion   → burn a share of the treasury (deflationary sink, fights
//                 hyper-inflation of the native token).
//   Consolidation → mint a stimulus grant from the treasury into the paying
//                 pool (protocol-subsidized tasks to stimulate activity).
func ApplyEconoPolicy(s *StateDB) {
	switch econoSnap.Phase {
	case 1: // Expansion
		econoPolicy.Phase = 1
		econoPolicy.BurnBps = EconoExpansionBurnBps
		econoPolicy.GrantBps = 0
		burnTreasuryShare(s, EconoExpansionBurnBps)
	default: // Consolidation (and cold-start)
		econoPolicy.Phase = 0
		econoPolicy.BurnBps = 0
		econoPolicy.GrantBps = EconoConsolidationGrantBps
		grantStimulus(s, EconoConsolidationGrantBps)
	}
}

// burnTreasuryShare burns burnBps/10000 of the quest treasury (0x03) — a
// deflationary sink active during expansion. Clamped to EconoMaxBurnBps.
func burnTreasuryShare(s *StateDB, burnBps uint64) {
	if burnBps > EconoMaxBurnBps {
		burnBps = EconoMaxBurnBps
	}
	if burnBps == 0 {
		return
	}
	treasury := s.GetOrCreateAccount(PrecompileAddrHex(0x03))
	if treasury.Balance == nil || treasury.Balance.Sign() == 0 {
		return
	}
	burn := new(big.Int).Mul(treasury.Balance, new(big.Int).SetUint64(burnBps))
	burn.Div(burn, big.NewInt(10_000))
	if burn.Sign() == 0 {
		return
	}
	treasury.Balance.Sub(treasury.Balance, burn)
	// Emit a sha256-core burn event for the analytics oracle.
	s.AddLog(PrecompileAddrHex(0x23),
		[][32]byte{sha256.Sum256([]byte("EconoBurn"))},
		burn.Bytes(), 0)
}

// grantStimulus tops up the paying treasury (0x03) from new emission share to
// fund protocol-subsidized tasks during consolidation. Here it simply ensures
// the treasury retains its replenishment headroom (the #71 emission share
// already flows in at DistributeBlockReward). The grantBps is recorded as the
// policy signal the oracle/dapp layer reads to launch subsidized tasks.
func grantStimulus(s *StateDB, grantBps uint64) {
	if grantBps > EconoMaxGrantBps {
		grantBps = EconoMaxGrantBps
	}
	// The actual subsidized-task funding is performed by routing the #71
	// emission share (TreasuryShareOf) into 0x03 — already live. This hook
	// records the policy and emits a signal event for the app layer.
	s.AddLog(PrecompileAddrHex(0x23),
		[][32]byte{sha256.Sum256([]byte("EconoStimulus"))},
		new(big.Int).SetUint64(grantBps).Bytes(), 0)
}

// GetEconoPolicy returns the live dynamic-variable state (for RPC / dashboard).
func GetEconoPolicy() EconoPolicy {
	return econoPolicy
}

func phaseName(p uint8) string {
	if p == 1 {
		return "Expansion"
	}
	return "Consolidation"
}

// EconoTaskPaidTopic is the sha256-core event id emitted on every payout.
// The app-layer EconoAnalytics oracle watches for this topic.
func EconoTaskPaidTopic() [32]byte {
	return sha256.Sum256([]byte("TaskPaid"))
}

// Ensure fmt is referenced (used by future structured logging of the policy).
var _ = fmt.Sprintf

// sha256SumBytes is a tiny wrapper so callers don't import crypto/sha256 just
// to hash a topic. Core hashing stays sha256 everywhere (Doctrine: sha256 is
// core, not app-layer).
func sha256SumBytes(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// isProTask classifies a task as "professional / high-tier" (licensed) vs
// "micro". Professional tasks require a Dox_Dev L2+ / ProfessionalBadge to
// accept — i.e. they are the skilled-labor tier whose premium the Task Yield
// Spread indicator measures. The set mirrors the licensed tiers in
// oracle_scheduler.go / doxDevBadge.go (L2+ gated actions).
var proTaskSet = map[string]bool{
	"badge-curate":    true, // L3 curator
	"oracle-feed":     true, // professional oracle
	"account-recovery": true, // guardian flow (verifier)
	"privacy-proof":   true, // ZK proof (verifier)
	"xchain-attest":   true, // cross-chain witness (verifier)
	"template-deploy": true, // L3 deploy
	"validator-72h":   true, // top-tier ladder
	"mrt-claim":       true, // verifier
	"dms-setup":       true, // verifier
}

func isProTask(taskIdBytes []byte) bool {
	task := string(taskIdBytes)
	if i := bytes.IndexByte(taskIdBytes, 0); i >= 0 {
		task = string(taskIdBytes[:i])
	}
	return proTaskSet[task]
}
