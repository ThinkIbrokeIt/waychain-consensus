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
		treasury := state.GetAccount(PrecompileAddrHex(0x03))
		claimantAcc := state.GetOrCreateAccount(claimantAddr)
		if treasury.Balance.Cmp(reward) >= 0 {
			treasury.Balance.Sub(treasury.Balance, reward)
			claimantAcc.Balance.Add(claimantAcc.Balance, reward)
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
	}
	return nil, fmt.Errorf("unknown selector")
}

func taskRewardAmount(taskIdBytes []byte) *big.Int {
	task := string(taskIdBytes)
	rewards := map[string]uint64{
		"bridge-test": 50, "oracle-sign": 25,
		"badge-deploy": 100, "badge-verify": 200,
		"first-swap": 10, "first-lock": 25,
		"twitter-follow": 10, "telegram-join": 5,
		"mrt-walkthrough": 300,
	}
	if amt, ok := rewards[task]; ok {
		return big.NewInt(int64(amt))
	}
	return big.NewInt(0)
}

func encodeBytes(b []byte) []byte {
	return b
}