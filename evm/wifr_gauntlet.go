package evm

import (
	"fmt"
	"math/big"
)

// WIFRGantletRewards is the native WayChain WIFR reward surface.
// It is exposed as precompile 0x21 and uses the same storage model as the other native protocol surfaces.

const (
	wifrSlotMainPool      byte = 0x00
	wifrSlotEarlyWorm     byte = 0x01
	wifrSlotGrandmaster   byte = 0x02
	wifrSlotPioneerClaims byte = 0x03
)

var (
	wifrInitializedKey    = storageKey([]byte("wifr:initialized"))
	wifrMainPoolInitial   = new(big.Int).Mul(big.NewInt(1_200_000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	wifrPioneerClaimReward = new(big.Int).Mul(big.NewInt(50), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
)

type WIFRGantletRewards struct {
	State *StateDB
}

func wifrAccount(state *StateDB) *Account {
	return state.GetOrCreateAccount(PrecompileAddrHex(0x21))
}

func wifrPoolKey(slot byte) [32]byte {
	return storageKey([]byte(fmt.Sprintf("wifr:pool:%02x", slot)))
}

func wifrClaimKey(address string) [32]byte {
	return storageKey([]byte("wifr:claim:" + address))
}

func (w *WIFRGantletRewards) IsInitialized() bool {
	acc := wifrAccount(w.State)
	return acc.Storage[wifrInitializedKey] != [32]byte{}
}

func (w *WIFRGantletRewards) EnsureInitialized() error {
	if w.IsInitialized() {
		return nil
	}
	return w.Initialize()
}

func (w *WIFRGantletRewards) Initialize() error {
	acc := wifrAccount(w.State)
	acc.Storage[wifrPoolKey(wifrSlotMainPool)] = writeSlot(new(big.Int).Set(wifrMainPoolInitial))
	acc.Storage[wifrPoolKey(wifrSlotEarlyWorm)] = writeSlot(big.NewInt(0))
	acc.Storage[wifrPoolKey(wifrSlotGrandmaster)] = writeSlot(big.NewInt(0))
	acc.Storage[wifrInitializedKey] = [32]byte{1}
	return nil
}

func (w *WIFRGantletRewards) getPool(slot byte) *big.Int {
	acc := wifrAccount(w.State)
	return readBigInt(acc.Storage[wifrPoolKey(slot)])
}

func (w *WIFRGantletRewards) setPool(slot byte, amount *big.Int) {
	acc := wifrAccount(w.State)
	acc.Storage[wifrPoolKey(slot)] = writeSlot(amount)
}

func (w *WIFRGantletRewards) GetRemainingRewardsBig(poolId uint64) *big.Int {
	slot := wifrSlotMainPool
	switch poolId {
	case 1:
		slot = wifrSlotMainPool
	case 2:
		slot = wifrSlotEarlyWorm
	case 3:
		slot = wifrSlotGrandmaster
	}
	return new(big.Int).Set(w.getPool(slot))
}

func (w *WIFRGantletRewards) ClaimPioneer(address string) error {
	acc := wifrAccount(w.State)
	claimKey := wifrClaimKey(address)
	if existing := acc.Storage[claimKey]; existing != [32]byte{} {
		return fmt.Errorf("already claimed")
	}
	acc.Storage[claimKey] = [32]byte{1}
	pool := w.getPool(wifrSlotMainPool)
	if pool.Cmp(wifrPioneerClaimReward) < 0 {
		return fmt.Errorf("insufficient rewards")
	}
	pool.Sub(pool, wifrPioneerClaimReward)
	w.setPool(wifrSlotMainPool, pool)
	return nil
}

func (w *WIFRGantletRewards) GetTotalRemainingBig() *big.Int {
	total := new(big.Int)
	for _, slot := range []byte{wifrSlotMainPool, wifrSlotEarlyWorm, wifrSlotGrandmaster} {
		total.Add(total, w.getPool(slot))
	}
	return total
}

func (w *WIFRGantletRewards) GetRemainingRewards(poolId uint64) uint64 {
	return w.GetRemainingRewardsBig(poolId).Uint64()
}

func (w *WIFRGantletRewards) GetTotalRemaining() uint64 {
	return w.GetTotalRemainingBig().Uint64()
}
