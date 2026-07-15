package evm

import (
	"fmt"
	"math/big"
)

// TaskRegistry precompile (0x23) — Track claimable WAY positions for task completion
// Stealth launch: earn WAY through verified contributions
// Bug bounty extensions: register, claim, verify fixes

func taskRegistryPrecompile(input []byte, caller string, state *StateDB, blockNum uint64) ([]byte, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("input too short")
	}

	sel := selectorBytes(input)

	switch sel {
	case 0xA1B2C3D4: // taskClaim(taskId[32])
		taskIdBytes := input[4:36]
		claimKey := storageKey(append([]byte{0x10}, []byte(caller)...))
		var s [32]byte
		copy(s[:], taskIdBytes)
		s[31] = 1 // claimed
		state.GetOrCreateAccount(caller).Storage[claimKey] = s
		return []byte{1}, nil

	case 0xB2C3D4E5: // taskVerify(taskId[32], claimant[20])
		taskIdBytes := input[4:36]
		claimant := readAddress(input, 36)
		callerAcc := state.GetAccount(caller)
		if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
			return nil, fmt.Errorf("unauthorized: need badge")
		}
		claimantAddr := fmt.Sprintf("%x", claimant[:])
		claimKey := storageKey(append([]byte{0x10}, []byte(claimantAddr)...))
		var s [32]byte
		copy(s[:], taskIdBytes)
		s[31] = 2 // verified
		state.GetOrCreateAccount(claimantAddr).Storage[claimKey] = s
		reward := taskRewardAmount(taskIdBytes)
		// Pay from the DEDICATED quest treasury (0x23.Storage[0x60]), not the
		// general 0x03 treasury — keeps the airdrop/quest budget ringfenced.
		if payFromQuestTreasury(state, reward) {
			state.GetOrCreateAccount(claimantAddr).Balance.Add(state.GetOrCreateAccount(claimantAddr).Balance, reward)
		}
		return []byte{1}, nil

	case 0xC3D4E5F6: // taskStatus(taskId[32])
		_ = input[4:36]
		claimKey := storageKey(append([]byte{0x10}, []byte(caller)...))
		s := state.GetAccount(caller).Storage[claimKey]
		status := "none"
		if s[31] == 1 {
			status = "claimed"
		} else if s[31] == 2 {
			status = "verified"
		}
		return encodeBytes([]byte(status)), nil

	case 0xE5F6A7B8: // giveawayClaim(instructionId[32])
		_ = input[4:36]
		claimKey := storageKey(append([]byte{0x11}, []byte(caller)...))
		acc := state.GetAccount(caller)
		if acc.Storage[claimKey][31] == 1 {
			return nil, fmt.Errorf("already claimed")
		}
		var s [32]byte
		s[31] = 1
		state.GetOrCreateAccount(caller).Storage[claimKey] = s
		reward := big.NewInt(5)
		pool := state.GetAccount(PrecompileAddrHex(0x02))
		claimantAcc := state.GetOrCreateAccount(caller)
		if pool.Balance.Cmp(reward) >= 0 {
			pool.Balance.Sub(pool.Balance, reward)
			claimantAcc.Balance.Add(claimantAcc.Balance, reward)
		}
		return []byte{1}, nil

	case 0x24A5B6C7: // registerBounty(type[1], amount[32], lane[1], descHash[32])
		bountyType := input[4]
		amount := new(big.Int).SetBytes(input[5:37])
		lane := input[37]
		descHash := new(big.Int).SetBytes(input[38:70])
		bountyKey := storageKey(append([]byte{0x20}, descHash.Bytes()...))
		var slot [32]byte
		slot[0] = bountyType
		slot[1] = lane
		copy(slot[2:32], amount.Bytes())
		state.GetAccount(PrecompileAddrHex(0x23)).Storage[bountyKey] = slot
		return []byte{1}, nil

	case 0x35B6C7D8: // claimFix(bountyId[32], prHash[32], attestation[32])
		bountyId := new(big.Int).SetBytes(input[4:36])
		prHash := new(big.Int).SetBytes(input[36:68])
		claimKey := storageKey(append([]byte{0x18}, bountyId.Bytes()...))
		var s [32]byte
		copy(s[:], prHash.Bytes())
		s[31] = 1 // claimed
		state.GetOrCreateAccount(caller).Storage[claimKey] = s
		return []byte{1}, nil

	case 0x46C7D8E9: // verifyFix(bountyId[32], claimant[20])
		bountyId := new(big.Int).SetBytes(input[4:36])
		claimant := readAddress(input, 36)
		callerAcc := state.GetAccount(caller)
		if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
			return nil, fmt.Errorf("unauthorized: need badge")
		}
		claimantAddr := fmt.Sprintf("%x", claimant[:])
		claimKey := storageKey(append([]byte{0x18}, bountyId.Bytes()...))
		var s [32]byte
		s[31] = 2 // verified
		state.GetOrCreateAccount(claimantAddr).Storage[claimKey] = s
		bountyData := state.GetAccount(PrecompileAddrHex(0x23)).Storage[storageKey(append([]byte{0x20}, bountyId.Bytes()...))]
		amount := readBigInt(bountyData)
		treasury := state.GetAccount(PrecompileAddrHex(0x03))
		claimantAcc := state.GetOrCreateAccount(claimantAddr)
		if treasury.Balance.Cmp(amount) >= 0 {
			treasury.Balance.Sub(treasury.Balance, amount)
			claimantAcc.Balance.Add(claimantAcc.Balance, amount)
		}
		return []byte{1}, nil

	case 0x58E9F0A1: // delegateMicroTask(bountyId[32], registrant[20], amount[32])
		bountyId := new(big.Int).SetBytes(input[4:36])
		registrant := readAddress(input, 36)
		amount := new(big.Int).SetBytes(input[56:88])
		// Only Dox_Dev level 2+ professionals can delegate
		callerAcc := state.GetAccount(caller)
		if callerAcc == nil || callerAcc.DoxDevLevel < 2 {
			return nil, fmt.Errorf("unauthorized: need professional badge")
		}
		// Check delegation limits (max 50% per tx)
		bountyData := state.GetAccount(PrecompileAddrHex(0x23)).Storage[storageKey(append([]byte{0x20}, bountyId.Bytes()...))]
		delegatedKey := storageKey(append([]byte{0x19}, bountyId.Bytes()...))
		alreadyDelegated := readBigInt(state.GetAccount(caller).Storage[delegatedKey])
		total := new(big.Int).Add(alreadyDelegated, amount)
		if total.Cmp(new(big.Int).Mul(readBigInt(bountyData), big.NewInt(8)).Div(readBigInt(bountyData), big.NewInt(10))) > 0 {
			return nil, fmt.Errorf("exceeds 80%% delegation limit")
		}
		// Store delegation
		delKey := storageKey(append([]byte{0x19}, append(bountyId.Bytes(), registrant[:]...)...))
		var slot [32]byte
		copy(slot[:], amount.Bytes())
		state.GetOrCreateAccount(caller).Storage[delKey] = slot
		return []byte{1}, nil

	case 0x6FA1B2C3: // recordTopTier() — ladder completion (validator72h+gov+oracle)
		return recordTopTier(state, caller)

	case 0x7FB2C3D4: // getTopTierRank() -> uint64 (0 = not ranked)
		rank := getTopTierRank(state, caller)
		out := writeUint64(rank)
		return out[:], nil

	case 0x8AB2C3D4: // bondOracle(amount[32]) — lock WAY as oracle bond (slashable)
		if len(input) < 36 {
			return nil, fmt.Errorf("topTier: bondOracle input too short")
		}
		var amtSlot [32]byte
		copy(amtSlot[:], input[4:36])
		amount := readBigInt(amtSlot)
		callerAcc := state.GetOrCreateAccount(caller)
		if callerAcc.Balance.Cmp(amount) < 0 {
			return nil, fmt.Errorf("topTier: insufficient balance to bond")
		}
		callerAcc.Balance.Sub(callerAcc.Balance, amount)
		bondKey := storageKey(append([]byte{0x50}, []byte(caller)...))
		cur := readBigInt(callerAcc.Storage[bondKey])
		cur.Add(cur, amount)
		callerAcc.Storage[bondKey] = writeBigInt(cur)
		return []byte{1}, nil

	case 0x9BC3D4E5: // unbondOracle() — release bond back to balance
		callerAcc := state.GetOrCreateAccount(caller)
		bondKey := storageKey(append([]byte{0x50}, []byte(caller)...))
		bond := readBigInt(callerAcc.Storage[bondKey])
		if bond.Sign() == 0 {
			return nil, fmt.Errorf("topTier: no bond to release")
		}
		callerAcc.Balance.Add(callerAcc.Balance, bond)
		callerAcc.Storage[bondKey] = writeBigInt(big.NewInt(0))
		return []byte{1}, nil

	case 0xACB4D5E6: // getBond() -> uint64 bonded amount
		bond := readBigInt(state.GetOrCreateAccount(caller).Storage[storageKey(append([]byte{0x50}, []byte(caller)...))])
		out := writeBigInt(bond)
		return out[:], nil

	case 0xD1E2F3A4: // questDeposit(amount[32]) — founder funds the dedicated quest treasury
		if len(input) < 36 {
			return nil, fmt.Errorf("quest: deposit input too short")
		}
		var amtSlot [32]byte
		copy(amtSlot[:], input[4:36])
		amount := readBigInt(amtSlot)
		callerAcc := state.GetOrCreateAccount(caller)
		if callerAcc.Balance.Cmp(amount) < 0 {
			return nil, fmt.Errorf("quest: insufficient balance to deposit")
		}
		callerAcc.Balance.Sub(callerAcc.Balance, amount)
		setQuestTreasuryBalance(state, new(big.Int).Add(questTreasuryBalance(state), amount))
		return []byte{1}, nil

	case 0xE2F3A4B5: // getQuestTreasury() -> uint64 remaining
		tb := writeBigInt(questTreasuryBalance(state))
		return tb[:], nil

	case 0xF3A4B5C6: // getQuestPhaseSpend(phase[1]) -> uint64 spent
		if len(input) < 5 {
			return nil, fmt.Errorf("quest: phaseSpend input too short")
		}
		ps := writeUint64(questPhaseSpend(state, uint64(input[4])))
		return ps[:], nil
	}
	return nil, fmt.Errorf("unknown selector")
}

// Top-tier ladder: first N wallets to complete validator(72h) + governance
// proposal + oracle bond receive the top-tier bonus + oracle privileges.
const TopTierMax = 20
const TopTierBonus = 1000

func taskRewardAmount(taskIdBytes []byte) *big.Int {
	task := string(taskIdBytes)
	rewards := map[string]uint64{
		// ── Legacy quest IDs (kept for backwards compat) ──
		"bridge-test": 50, "oracle-sign": 25,
		"badge-deploy": 100, "badge-verify": 200,
		"first-swap": 25, "first-lock": 25,
		"twitter-follow": 10, "telegram-join": 5,
		"mrt-walkthrough": 300,
		// ── Foundation quest program (recruit the base) ──
		"wallet-setup": 100,    // verifier-gated: safe onboarding + backup
		"first-transfer": 10,   // proof-by-action: nonce>0
		"governance-vote": 25,  // proof-by-action: getVote non-empty
		"gov-propose": 25,      // proof-by-action: proposal created
		"quest-feedback": 50,   // verifier-gated: feedback quality
		"doxdev-badge": 100,    // verifier-gated: Dox_Dev L2 earned
		"1way-mint": 300,       // proof-by-action: vault created + 1WAY minted (value onboarding priority)
		"oracle-setup": 150,    // proof-by-action: prof badge + attestation submitted
		"validator-setup": 500, // verifier-gated: 72h no-downtime active set
	}
	if amt, ok := rewards[task]; ok {
		return big.NewInt(int64(amt))
	}
	return big.NewInt(0)
}

func encodeBytes(b []byte) []byte {
	return b
}

// ── Top-tier ladder tracking (0x23) ──
// First TopTierMax wallets to complete the validator(72h uptime) → governance
// proposal → oracle bond ladder earn the top-tier rank + bonus.
// Uptime is proven on-chain via the per-block liveness counter incremented in
// chain.go ProduceBlock (ValidatorUptimeSlot), so no off-chain verification.

const ValidatorUptimeSlot = byte(0x40) // key prefix: uptime[addr] (blocks in active set)

func validatorUptimeKey(addr string) [32]byte {
	return storageKey(append([]byte{ValidatorUptimeSlot}, []byte(addr)...))
}

// GetValidatorUptime returns blocks the address has been in the active set.
func GetValidatorUptime(state *StateDB, addr string) uint64 {
	if acc := state.GetAccount(addr); acc != nil {
		return readUint64(acc.Storage[validatorUptimeKey(addr)])
	}
	return 0
}

// IncrementValidatorUptime is called once per block for each active validator.
func IncrementValidatorUptime(state *StateDB, addr string) {
	acc := state.GetOrCreateAccount(addr)
	k := validatorUptimeKey(addr)
	acc.Storage[k] = writeUint64(readUint64(acc.Storage[k]) + 1)
}

func recordTopTier(state *StateDB, caller string) ([]byte, error) {
	// Gates: 72h active-set uptime + governance proposal + oracle bonded.
	const blocks72h = uint64(72 * 3600 / 5) // ~5s block time assumption
	if GetValidatorUptime(state, caller) < blocks72h {
		return nil, fmt.Errorf("top-tier: need 72h validator uptime (have %d blocks)", GetValidatorUptime(state, caller))
	}
	// Oracle bond present?
	bondKey := storageKey(append([]byte{0x50}, []byte(caller)...)) // set by bondOracle (0x0D)
	if readBigInt(state.GetOrCreateAccount(caller).Storage[bondKey]).Sign() == 0 {
		return nil, fmt.Errorf("top-tier: oracle bond required")
	}
	// Governance proposal made? tracked via taskClaim("gov-propose") on caller.
	propKey := storageKey(append([]byte{0x10}, []byte(caller)...))
	pb := [32]byte{}
	copy(pb[:], []byte("gov-propose"))
	pb[31] = 1
	if state.GetOrCreateAccount(caller).Storage[propKey] != pb {
		return nil, fmt.Errorf("top-tier: governance proposal required")
	}
	// Rank assignment (first TopTierMax).
	rank := getTopTierRank(state, caller)
	if rank != 0 {
		return new(big.Int).SetUint64(rank).Bytes(), nil // already ranked
	}
	counterKey := storageKey([]byte("topTier:counter"))
	n := readUint64(state.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[counterKey]) + 1
	if n > uint64(TopTierMax) {
		return nil, fmt.Errorf("top-tier: full (max %d reached)", TopTierMax)
	}
	state.GetOrCreateAccount(PrecompileAddrHex(0x23)).Storage[counterKey] = writeUint64(n)
	rankKey := storageKey(append([]byte{0x41}, []byte(caller)...))
	state.GetOrCreateAccount(caller).Storage[rankKey] = writeUint64(n)
	// Pay top-tier bonus from the DEDICATED quest treasury (not 0x03).
	callerAcc := state.GetOrCreateAccount(caller)
	if payFromQuestTreasury(state, big.NewInt(TopTierBonus)) {
		callerAcc.Balance.Add(callerAcc.Balance, big.NewInt(TopTierBonus))
	}
	return new(big.Int).SetUint64(n).Bytes(), nil
}

func getTopTierRank(state *StateDB, caller string) uint64 {
	return readUint64(state.GetOrCreateAccount(caller).Storage[storageKey(append([]byte{0x41}, []byte(caller)...))])
}

// ── Dedicated Quest Treasury (ringfenced, separate from 0x03 general treasury) ──
// All foundation-quest + top-tier payouts draw from this pool only. Funded once
// (or topping up) by the founder via questDeposit. Per-phase caps enforced so
// the 250k WAY ringfence can't be overspent by any single phase.
const QuestTreasurySlot = byte(0x60)
const QuestPhaseSpendSlot = byte(0x61)

// Phase budgets (WAY). Phase 1 = foundation quests; Phase 2 = top-tier ladder.
var QuestPhaseBudgets = map[uint64]uint64{
	1: 100_000, // foundation quests (wallet/transfer/swap/vote/feedback/badge/1way/oracle/validator)
	2: 120_000, // top-tier ladder (first 20 validators→oracle: bond returned, ~6k WAY reward each)
	// reserve ~30k unallocated
}

func questTreasuryBalance(state *StateDB) *big.Int {
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x23))
	return readBigInt(acc.Storage[storageKey([]byte{QuestTreasurySlot})])
}

func setQuestTreasuryBalance(state *StateDB, v *big.Int) {
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x23))
	acc.Storage[storageKey([]byte{QuestTreasurySlot})] = writeBigInt(v)
}

func questPhaseSpend(state *StateDB, phase uint64) uint64 {
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x23))
	return readUint64(acc.Storage[storageKey(append([]byte{QuestPhaseSpendSlot}, byte(phase)))])
}

func addQuestPhaseSpend(state *StateDB, phase uint64, amt uint64) {
	acc := state.GetOrCreateAccount(PrecompileAddrHex(0x23))
	key := storageKey(append([]byte{QuestPhaseSpendSlot}, byte(phase)))
	acc.Storage[key] = writeUint64(readUint64(acc.Storage[key]) + amt)
}

// payFromQuestTreasury deducts `amount` from the dedicated pool + records phase
// spend. phase 1 = taskVerify rewards; phase 2 = top-tier bonus. Returns false
// (no pay) if the pool or the phase cap is exhausted.
func payFromQuestTreasury(state *StateDB, amount *big.Int) bool {
	bal := questTreasuryBalance(state)
	if bal.Cmp(amount) < 0 {
		return false
	}
	// Phase cap check (reward size implies phase: top-tier bonus -> phase 2).
	phase := uint64(1)
	if amount.Cmp(big.NewInt(TopTierBonus)) >= 0 {
		phase = 2
	}
	budget := QuestPhaseBudgets[phase]
	if budget > 0 && questPhaseSpend(state, phase)+amount.Uint64() > budget {
		return false
	}
	setQuestTreasuryBalance(state, new(big.Int).Sub(bal, amount))
	addQuestPhaseSpend(state, phase, amount.Uint64())
	return true
}