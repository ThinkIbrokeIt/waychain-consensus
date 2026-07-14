package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"math/big"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
	"github.com/ThinkIbrokeIt/waychain-consensus/store"
)

// Transaction is a WayChain transaction
type Transaction struct {
	Nonce    uint64
	From     string   // Sender address (hex public key)
	To       string   // Recipient address (hex, empty for contract creation)
	Value    *big.Int
	GasLimit uint64
	GasPrice uint64
	Data     []byte   // Calldata or init code
	Hash     [32]byte
	Signature []byte  // Ed25519 signature
	Lane     evm.LaneType // Execution lane (0=consensus, 1=oracle, 2=private)
	EncryptedData []byte // Encrypted payload for PrivateLane/OracleLane
}

// NewTransaction creates a new transaction
func NewTransaction(nonce uint64, from, to string, value *big.Int, gasLimit uint64, data []byte) Transaction {
	tx := Transaction{
		Nonce:    nonce,
		From:     from,
		To:       to,
		Value:    value,
		GasLimit: gasLimit,
		Data:     data,
		Lane:     evm.ConsensusLane, // default to consensus lane
	}
	hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		nonce, from, to, value.String(), gasLimit, evm.ConsensusLane, len(data), data, []byte{})
	tx.Hash = sha256.Sum256([]byte(hashInput))
	return tx
}

// TxHash computes the signing hash of a transaction
func (tx *Transaction) TxHash() [32]byte {
	input := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
		tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
	return sha256.Sum256([]byte(input))
}

// TxPool holds pending transactions separated by lane
type TxPool struct {
	Consensus []Transaction // Lane 0: standard public transactions
	Oracle    []Transaction // Lane 1: oracle attestation processing
	Private   []Transaction // Lane 2: private transactions (encrypted)
}

func NewTxPool() *TxPool {
	return &TxPool{
		Consensus: make([]Transaction, 0),
		Oracle:    make([]Transaction, 0),
		Private:   make([]Transaction, 0),
	}
}

// Add adds a transaction to the appropriate lane pool
func (p *TxPool) Add(tx Transaction) {
	switch tx.Lane {
	case evm.PrivateLane:
		p.Private = append(p.Private, tx)
	case evm.OracleLane:
		p.Oracle = append(p.Oracle, tx)
	case evm.ConsensusLane:
		fallthrough
	default:
		p.Consensus = append(p.Consensus, tx)
	}
}

// PopConsensus gets transactions for consensus execution
func (p *TxPool) PopConsensus(count int) []Transaction {
	if count > len(p.Consensus) {
		count = len(p.Consensus)
	}
	if count == 0 {
		return nil
	}
	txs := p.Consensus[:count]
	p.Consensus = p.Consensus[count:]
	return txs
}

// PopOracle gets transactions for oracle lane execution
func (p *TxPool) PopOracle(count int) []Transaction {
	if count > len(p.Oracle) {
		count = len(p.Oracle)
	}
	if count == 0 {
		return nil
	}
	txs := p.Oracle[:count]
	p.Oracle = p.Oracle[count:]
	return txs
}

// PopPrivate gets transactions for private lane execution
func (p *TxPool) PopPrivate(count int) []Transaction {
	if count > len(p.Private) {
		count = len(p.Private)
	}
	if count == 0 {
		return nil
	}
	txs := p.Private[:count]
	p.Private = p.Private[count:]
	return txs
}

// Len returns total pending transactions
func (p *TxPool) Len() int {
	return len(p.Consensus) + len(p.Oracle) + len(p.Private)
}

// BlockWithTx is a block that carries EVM state
type BlockWithTx struct {
	Height      uint64
	Proposer    ValidatorID
	Timestamp   int64
	PrevHash    [32]byte
	Transactions []Transaction
	StateRoot   [32]byte  // Hash of EVM state after executing txs
	Hash        [32]byte
}

func (b *BlockWithTx) ComputeHash() [32]byte {
	data := fmt.Sprintf("%d:%v:%d:%x:%d:%x",
		b.Height, b.Proposer, b.Timestamp, b.PrevHash, len(b.Transactions), b.StateRoot)
	return sha256.Sum256([]byte(data))
}

// Chain connects the consensus engine to the EVM execution layer
type Chain struct {
	State      *evm.StateDB
	Pool       *TxPool
	EVM        *evm.EVM
	Blocks     []*BlockWithTx
	Height     uint64
	Store      *store.Store // persistent storage (nil = in-memory only)
	Staking    *ProgressiveStaking

	// Callbacks for real-time event streaming
	OnNewBlock func(block *BlockWithTx)
}

// NewChain creates a new chain instance
func NewChain() *Chain {
	state := evm.NewStateDB()
	// Fund some test accounts
	funder := state.GetOrCreateAccount("funder")
	funder.Balance.SetUint64(1_000_000_000)

	evmEngine := evm.NewEVM(state, evm.ConsensusLane, 1, uint64(time.Now().Unix()), 10008, 30_000_000, "")

	chain := &Chain{
		State:   state,
		Pool:    NewTxPool(),
		EVM:     evmEngine,
		Blocks:  make([]*BlockWithTx, 0),
		Height:  0,
		Staking: NewProgressiveStaking(DefaultAnnualInflationPct, DefaultBlockTimeSec, EpochLength), // 7% of supply/year, 3s blocks, 10000-block epochs
	}

	// Initialize precompile state at genesis
	chain.InitPrecompiles()

	return chain
}

// InitPrecompiles initializes the protocol precompile accounts with genesis state
func (c *Chain) InitPrecompiles() {
	// ── DoxDevBadge (0x13): create account, set 3 initial curators ──
	badgeAddr := evm.PrecompileAddrHex(0x13)
	badgeAcc := c.State.GetOrCreateAccount(badgeAddr)
	// Slot 0 = totalBadges, Slot 1 = curatorCount
	// Set curator count to 3
	var count [32]byte
	bi := new(big.Int).SetUint64(3)
	bi.FillBytes(count[:])
	badgeAcc.Storage[[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}] = count

	// Register alice, bob, treasury as initial curators
	c.registerCurator(badgeAcc, "alice")
	c.registerCurator(badgeAcc, "bob")
	c.registerCurator(badgeAcc, "treasury")

	// Issue badges for genesis accounts
	c.issueGenesisBadge(badgeAcc, "alice", 3, 0)  // L3, never expires
	c.issueGenesisBadge(badgeAcc, "bob", 2, 0)    // L2
	c.issueGenesisBadge(badgeAcc, "treasury", 3, 0) // L3

	// ── BIJO (0x14): create account, set supply ──
	bijoAddr := evm.PrecompileAddrHex(0x14)
	bijoAcc := c.State.GetOrCreateAccount(bijoAddr)
	// Set totalSupply
	supply := new(big.Int).Set(evm.BijoSupply)
	var supplySlot [32]byte
	supply.FillBytes(supplySlot[:])
	// Slot 0 = totalSupply
	bijoAcc.Storage[[32]byte{}] = supplySlot

	// Transfer enabled = false (slot 1 = 0, default)
	// Set governance address (slot 2)
	bijoAcc.Storage[[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}] = [32]byte{}

	// Fund genesis allocations (70% storage, 10% airdrop, etc.)
	// For demo: give alice some BIJO
	aliceBijo := new(big.Int).Div(supply, big.NewInt(100)) // 1%
	var aliceDev [20]byte
	copy(aliceDev[:], []byte("alice"))
	aliceKey := sha256.Sum256(append([]byte{0x10}, aliceDev[:]...))
	var aliceBal [32]byte
	aliceBijo.FillBytes(aliceBal[:])
	bijoAcc.Storage[aliceKey] = aliceBal

	// ── DeadMansSwitch (0x15): create account ──
	c.State.GetOrCreateAccount(evm.PrecompileAddrHex(0x15))

	// ── BitcoinRegistry (0x16): create account ──
	c.State.GetOrCreateAccount(evm.PrecompileAddrHex(0x16))

	// ── StorageEndowment (0x17): create account ──
	endowAddr := evm.PrecompileAddrHex(0x17)
	endowAcc := c.State.GetOrCreateAccount(endowAddr)
	// Set startTime to current block
	startTime := c.Height
	var st [32]byte
	new(big.Int).SetUint64(startTime).FillBytes(st[:])
	endowAcc.Storage[[32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}] = st

	// ── WIFR Gauntlet (0x21): create account and initialize pools ──
	wifrAddr := evm.PrecompileAddrHex(0x21)
	wifrAcc := c.State.GetOrCreateAccount(wifrAddr)
	_ = wifrAcc
	if err := (&evm.WIFRGantletRewards{State: c.State}).Initialize(); err != nil {
		panic(err)
	}
}

func (c *Chain) issueGenesisBadge(badgeAcc *evm.Account, developer string, level uint8, validityPeriod uint64) {
	// Pad developer string to 20 bytes to match precompile address encoding
	var devAddr [20]byte
	copy(devAddr[:], []byte(developer))

	// Increment totalBadges
	totalKey := [32]byte{} // slot 0
	existing := badgeAcc.Storage[totalKey]
	total := new(big.Int).SetBytes(existing[:]).Uint64() + 1
	var totalB [32]byte
	new(big.Int).SetUint64(total).FillBytes(totalB[:])
	badgeAcc.Storage[totalKey] = totalB

	// Write badge data using 20-byte padded address to match precompile
	badgeKey := sha256.Sum256(append([]byte{0x10}, devAddr[:]...))
	var data [32]byte
	data[0] = level
	if validityPeriod > 0 {
		new(big.Int).SetUint64(c.Height + validityPeriod).FillBytes(data[1:9])
	}
	data[9] = 0 // not revoked
	new(big.Int).SetUint64(c.Height).FillBytes(data[17:25])
	badgeAcc.Storage[badgeKey] = data
}

// registerCurator marks an address as a Dox_Dev curator in the precompile storage
func (c *Chain) registerCurator(badgeAcc *evm.Account, developer string) {
	var devAddr [20]byte
	copy(devAddr[:], []byte(developer))
	curatorKey := sha256.Sum256(append([]byte{0x30}, devAddr[:]...))
	var one [32]byte
	one[31] = 1
	badgeAcc.Storage[curatorKey] = one
}

// ── Persistent Storage ──

// OpenStore opens or creates a persistent store at the given path
// and loads chain state from it. Returns the existing chain if loaded.
func (c *Chain) OpenStore(dbPath string) (*store.Store, error) {
	s, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	c.Store = s

	// Load previous state
	if s.Height() > 0 {
		state, err := s.LoadAllAccounts()
		if err != nil {
			return nil, fmt.Errorf("chain: load state: %w", err)
		}
		c.State = state
		c.Height = s.Height()
		// Rebuild EVM with loaded state
		c.EVM = evm.NewEVM(state, evm.ConsensusLane, c.Height+1, uint64(time.Now().Unix()), 10008, 30_000_000, "")
		if err := (&evm.WIFRGantletRewards{State: c.State}).EnsureInitialized(); err != nil {
			return nil, fmt.Errorf("chain: init wifr: %w", err)
		}

		// Log latest blocks
		blocks, _ := s.LatestBlocks(5)
		for _, b := range blocks {
			c.Blocks = append(c.Blocks, &BlockWithTx{
				Height: b.Height,
			})
		}
		fmt.Printf("  🔄 Restored from disk: height=%d, accounts=%d\n", c.Height, len(state.Accounts))
	}

	return s, nil
}

// CloseStore closes the persistent store
func (c *Chain) CloseStore() error {
	if c.Store != nil {
		return c.Store.Close()
	}
	return nil
}

// Sync persists all current state to disk. Call after every block commit.
func (c *Chain) Sync(proposer string, txCount int, hash, prevHash [32]byte) error {
	if c.Store == nil {
		return nil // in-memory mode
	}
	// Save all accounts
	if err := c.Store.SaveAllAccounts(c.State); err != nil {
		return fmt.Errorf("chain: sync accounts: %w", err)
	}
	// Save block metadata
	stateRef := fmt.Sprintf("%x", hash[:4])
	if err := c.Store.SaveBlock(c.Height, proposer, txCount, hash, prevHash, stateRef); err != nil {
		return fmt.Errorf("chain: sync block: %w", err)
	}
	return nil
}

// SyncTxs persists the transactions from a block and builds a tx hash index.
func (c *Chain) SyncTxs(block *BlockWithTx) error {
	if c.Store == nil || len(block.Transactions) == 0 {
		return nil
	}
	txs := make([]store.TxData, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = store.TxData{
			Nonce:     tx.Nonce,
			From:      tx.From,
			To:        tx.To,
			Value:     tx.Value.Bytes(),
			GasLimit:  tx.GasLimit,
			GasPrice:  tx.GasPrice,
			Data:      tx.Data,
			Hash:      tx.Hash,
			Signature: tx.Signature,
		}
		// Index: tx hash → block height + position
		if err := c.Store.SaveTxIndex(tx.Hash, block.Height, uint16(i)); err != nil {
			return fmt.Errorf("chain: tx index: %w", err)
		}
	}
	if err := c.Store.SaveBlockTxs(block.Height, txs); err != nil {
		return fmt.Errorf("chain: save txs: %w", err)
	}
	return nil
}

// LoadTxFromStore looks up a transaction by hash in the persistent store.
// Returns nil if not found.
func (c *Chain) LoadTxFromStore(hash [32]byte) (*Transaction, uint64, error) {
	if c.Store == nil {
		return nil, 0, nil
	}
	height, txIdx, found, err := c.Store.LoadTxIndex(hash)
	if err != nil || !found {
		return nil, 0, err
	}
	txs, err := c.Store.LoadBlockTxs(height)
	if err != nil || int(txIdx) >= len(txs) {
		return nil, 0, err
	}
	txd := txs[txIdx]
	tx := &Transaction{
		Nonce:     txd.Nonce,
		From:      txd.From,
		To:        txd.To,
		Value:     new(big.Int).SetBytes(txd.Value),
		GasLimit:  txd.GasLimit,
		GasPrice:  txd.GasPrice,
		Data:      txd.Data,
		Hash:      txd.Hash,
		Signature: txd.Signature,
	}
	return tx, height, nil
}

// DeployTestContract deploys a simple storage contract for testing
func (c *Chain) DeployTestContract(deployer string) (string, error) {
	// Minimal contract that stores calldata at slot 0 and returns stored value
	code := []byte{
		0x60, 0x00, 0x35, // PUSH1 0 CALLDATALOAD
		0x60, 0x00, 0x55, // PUSH1 0 SSTORE
		0x60, 0x00, 0x54, // PUSH1 0 SLOAD
		0x60, 0x00, 0x52, // PUSH1 0 MSTORE
		0x60, 0x20, 0x60, 0x00, 0xF3, // PUSH1 32 PUSH1 0 RETURN
	}
	return c.EVM.DeployContractFromCode(deployer, code, evm.ClassA)
}

// ProduceBlock builds and executes a new block with pending transactions
func (c *Chain) ProduceBlock(proposer ValidatorID) *BlockWithTx {
	c.Height++

	var prevHash [32]byte
	if len(c.Blocks) > 0 {
		prevHash = c.Blocks[len(c.Blocks)-1].Hash
	}

	// Take up to 10 consensus txs from pool (plus any oracle/private lanes)
	popped := c.Pool.PopConsensus(10)

	// Execute transactions and collect only successful ones
	var executed []Transaction

	for i := range popped {
		tx := &popped[i]
		sender := c.State.GetOrCreateAccount(tx.From)

		// Verify signature if present
		if len(tx.Signature) > 0 {
			pub, err := ParsePubKey(tx.From)
			if err != nil {
				continue
			}
			// Compute signing hash (includes calldata)
			sigHash := tx.TxHash()
			if !ed25519.Verify(pub, sigHash[:], tx.Signature) {
				continue // Invalid signature
			}
		}

		// Nonce check
		if tx.Nonce != sender.Nonce {
			continue // Wrong nonce
		}

		// Deploy gate: if this is a contract creation tx, enforce Dox_Dev Level 2+
		if tx.To == "" {
			if err := evm.CanDeployContract(sender.DoxDevLevel); err != nil {
				continue // Reject deploy from unverified address
			}
		}

		// Gas price default
		gasPrice := tx.GasPrice
		if gasPrice == 0 {
			gasPrice = 1 // minimum gas price
		}

		// Check sender has enough balance for gas + value
		txCost := new(big.Int).SetUint64(tx.GasLimit * gasPrice)
		txCost.Add(txCost, tx.Value)
		if sender.Balance.Cmp(txCost) < 0 {
			continue // Insufficient funds
		}

		// Execute via EVM with transaction's lane
		// Create EVM instance with correct lane for this transaction
		txEVM := evm.NewEVM(c.State, tx.Lane, c.Height, uint64(time.Now().Unix()), 10008, tx.GasLimit, "")
		
		ctx := &evm.CallContext{
			Caller:   tx.From,
			Address:  tx.To,
			Value:    tx.Value,
			GasLimit: tx.GasLimit,
			Calldata: tx.Data,
		}
		result := txEVM.Execute(ctx)

		// Deduct actual gas cost (not full gas limit)
		cost := new(big.Int).SetUint64(result.GasUsed * gasPrice)
		cost.Add(cost, tx.Value)
		sender.Balance.Sub(sender.Balance, cost)
		sender.Nonce++

		if result.Error != nil {
			continue
		}

		// Tx executed successfully — include in block
		executed = append(executed, *tx)
	}

	// Compute state root (simplified: hash of all account data)
	stateHash := sha256.Sum256([]byte(fmt.Sprintf("%v", c.State.Accounts)))

	block := &BlockWithTx{
		Height:       c.Height,
		Proposer:     proposer,
		Timestamp:    time.Now().Unix(),
		PrevHash:     prevHash,
		Transactions: executed,
		StateRoot:    stateHash,
	}
	block.Hash = block.ComputeHash()
	c.Blocks = append(c.Blocks, block)

	// Execute due time-scheduled tasks
	te := evm.NewTimeExecution(c.State)
	dueTasks, _ := te.ExecuteDueTasks(c.Height)
	if len(dueTasks) > 0 {
		for _, taskID := range dueTasks {
			// Emit execution event
			task, _ := te.GetTask(taskID)
			if task != nil {
				addr := evm.PrecompileAddrHex(0x0D)
				c.State.AddLog(addr, [][32]byte{
					task.FeedID,
					taskID,
				}, []byte{byte(task.ExecutionCount)}, c.Height)
			}
		}
	}

	// Rollover the per-epoch emission cap when a new epoch begins.
	if c.Staking != nil && c.Staking.EpochLength > 0 && c.Height%c.Staking.EpochLength == 0 {
		c.Staking.RolloverEpoch()
	}

	// Distribute staking rewards for this block (anchored to the 7% annual cap).
	if c.Staking != nil {
		rewards := c.Staking.DistributeBlockReward(c.Height)
		for id, amount := range rewards {
			if amount > 0 {
				acc := c.State.GetOrCreateAccount(id.String())
				acc.Balance.Add(acc.Balance, new(big.Int).SetUint64(amount))
			}
		}
	}

	// Notify subscribers about the new block
	if c.OnNewBlock != nil {
		c.OnNewBlock(block)
	}

	return block
}

// PrintChainStatus displays the current chain state
func (c *Chain) PrintChainStatus() {
	fmt.Printf("\n═══ WayChain Full Stack ═══\n")
	fmt.Printf("Blocks: %d\n", len(c.Blocks))
	fmt.Printf("Accounts: %d\n", len(c.State.Accounts))
	fmt.Printf("Pending txs: %d\n", c.Pool.Len())
	fmt.Println()

	if len(c.Blocks) > 0 {
		last := c.Blocks[len(c.Blocks)-1]
		fmt.Printf("Latest block: #%d\n", last.Height)
		fmt.Printf("  Proposer: %v\n", last.Proposer)
		fmt.Printf("  Txs: %d\n", len(last.Transactions))
		fmt.Printf("  StateRoot: %x...\n", last.StateRoot[:4])
	}

	fmt.Println("\nAccounts:")
	for addr, acc := range c.State.Accounts {
		class := "None"
		if acc.ContractClass > 0 {
			class = fmt.Sprintf("Class %s", acc.ContractClass)
		}
		fmt.Printf("  %s | balance: %d | nonce: %d | level: %d | %s\n",
			addr, acc.Balance, acc.Nonce, acc.DoxDevLevel, class)
	}

	// Print block history
	fmt.Println("\nBlock history:")
	for _, b := range c.Blocks {
		fmt.Printf("  #%d | proposer: %v | txs: %d | hash: %x...\n",
			b.Height, b.Proposer, len(b.Transactions), b.Hash[:4])
	}
}