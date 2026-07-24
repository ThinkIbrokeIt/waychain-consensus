// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package evm

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// deployContract handles contract creation from a transaction with empty To address.
func (evm *EVM) deployContract(ctx *CallContext) *ExecutionResult {
	// Get deployer account
	deployer := evm.State.GetOrCreateAccount(ctx.Caller)

	// Derive 20-byte EVM address from the full pubkey
	deployerHash := sha256.Sum256([]byte(ctx.Caller))
	deployerAddr := deployerHash[:20]

	// Compute contract address: keccak256(rlp([20byte_addr, nonce]))[12:]
	var rlpBuf []byte
	if deployer.Nonce < 56 {
		listLen := byte(22)
		rlpBuf = append(rlpBuf, 0xc0+listLen)
		rlpBuf = append(rlpBuf, 0x80+20)
		rlpBuf = append(rlpBuf, deployerAddr...)
		rlpBuf = append(rlpBuf, byte(deployer.Nonce))
	} else {
		nonceBytes := new(big.Int).SetUint64(deployer.Nonce).Bytes()
		itemLen := 1 + 20 + 1 + len(nonceBytes)
		rlpBuf = append(rlpBuf, 0xc0+byte(itemLen))
		rlpBuf = append(rlpBuf, 0x80+20)
		rlpBuf = append(rlpBuf, deployerAddr...)
		rlpBuf = append(rlpBuf, 0x80+byte(len(nonceBytes)))
		rlpBuf = append(rlpBuf, nonceBytes...)
	}

	kh := sha3.NewLegacyKeccak256()
	kh.Write(rlpBuf)
	addrHash := kh.Sum(nil)
	contractAddr := fmt.Sprintf("%x", addrHash[12:])

	// Execute init code in the context of the new contract
	// Note: nonce is NOT incremented here — ProduceBlock does it after execution
	initCtx := &CallContext{
		Caller:   ctx.Caller,
		Address:  contractAddr,
		Value:    ctx.Value,
		GasLimit: ctx.GasLimit,
		Calldata: ctx.Calldata,
	}

	result := evm.Execute(initCtx)

	// If execution succeeded and returned data, store it as runtime code
	if result.Error == nil && len(result.ReturnData) > 0 {
		contract := evm.State.GetOrCreateAccount(contractAddr)
		contract.Code = result.ReturnData
		contract.CodeHash = sha256.Sum256(result.ReturnData)
	}

	return result
}