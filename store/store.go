package store

import (
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
	"go.etcd.io/bbolt"
)

// Store wraps a BoltDB database for WayChain persistent state
type Store struct {
	db     *bbolt.DB
	path   string
	height uint64 // cached latest block height
}

// Open opens or creates a WayChain store at the given path
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	// Ensure buckets exist
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{"accounts", "blocks", "meta", "node"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: init buckets: %w", err)
	}

	s := &Store{db: db, path: path}

	// Read cached height
	_ = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("meta"))
		if v := b.Get([]byte("height")); len(v) == 8 {
			s.height = binary.BigEndian.Uint64(v)
		}
		return nil
	})

	return s, nil
}

// Close closes the database
func (s *Store) Close() error {
	return s.db.Close()
}

// Path returns the database path
func (s *Store) Path() string { return s.path }

// Height returns the latest stored block height
func (s *Store) Height() uint64 { return s.height }

// ── Account State ──

// SaveAccount writes a single account to disk
func (s *Store) SaveAccount(addr string, acc *evm.Account) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("accounts"))
		data, err := serializeAccount(acc)
		if err != nil {
			return err
		}
		return b.Put([]byte(addr), data)
	})
}

// LoadAccount reads a single account from disk
func (s *Store) LoadAccount(addr string) (*evm.Account, error) {
	var acc *evm.Account
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("accounts"))
		data := b.Get([]byte(addr))
		if data == nil {
			acc = nil
			return nil
		}
		var err error
		acc, err = deserializeAccount(data)
		return err
	})
	return acc, err
}

// SaveAllAccounts writes all accounts in a StateDB to disk
func (s *Store) SaveAllAccounts(state *evm.StateDB) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("accounts"))
		for addr, acc := range state.Accounts {
			data, err := serializeAccount(acc)
			if err != nil {
				return fmt.Errorf("store: serialize %s: %w", addr, err)
			}
			if err := b.Put([]byte(addr), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadAllAccounts loads all accounts from disk into a StateDB
func (s *Store) LoadAllAccounts() (*evm.StateDB, error) {
	state := evm.NewStateDB()
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("accounts"))
		return b.ForEach(func(k, v []byte) error {
			acc, err := deserializeAccount(v)
			if err != nil {
				return err
			}
			state.Accounts[string(k)] = acc
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

// ── Block Storage ──

// BlockData is the minimal block data saved to disk
type BlockData struct {
	Height   uint64
	Proposer string
	TxCount  int
	Hash     [32]byte
	PrevHash [32]byte
	StateRef string // placeholder for state root reference
}

// SaveBlock persists a block to disk
func (s *Store) SaveBlock(height uint64, proposer string, txCount int, hash, prevHash [32]byte, stateRef string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], height)

		bd := BlockData{
			Height:   height,
			Proposer: proposer,
			TxCount:  txCount,
			Hash:     hash,
			PrevHash: prevHash,
			StateRef: stateRef,
		}
		data, err := serializeGob(bd)
		if err != nil {
			return err
		}
		if err := b.Put(buf[:], data); err != nil {
			return err
		}

		// Update height metadata
		meta := tx.Bucket([]byte("meta"))
		meta.Put([]byte("height"), buf[:])
		s.height = height
		return nil
	})
}

// LoadBlock reads a block by height
func (s *Store) LoadBlock(height uint64) (*BlockData, error) {
	var bd *BlockData
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], height)
		data := b.Get(buf[:])
		if data == nil {
			return nil
		}
		var v BlockData
		if err := deserializeGob(data, &v); err != nil {
			return err
		}
		bd = &v
		return nil
	})
	return bd, err
}

// LatestBlocks returns the last N blocks
func (s *Store) LatestBlocks(n int) ([]BlockData, error) {
	var blocks []BlockData
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		c := b.Cursor()
		k, v := c.Last()
		for i := 0; i < n && k != nil; i++ {
			var bd BlockData
			if err := deserializeGob(v, &bd); err != nil {
				return err
			}
			blocks = append(blocks, bd)
			k, v = c.Prev()
		}
		return nil
	})
	// Reverse to chronological order
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}
	return blocks, err
}

// ── Node Identity ──

// NodeInfo stores the node's identity
type NodeInfo struct {
	ID        string `json:"id"`
	ListenAddr string `json:"listen_addr"`
	RPCAddr   string `json:"rpc_addr"`
	NodeKey   []byte `json:"node_key,omitempty"`
}

// SaveNodeInfo writes node identity to disk
func (s *Store) SaveNodeInfo(info *NodeInfo) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("node"))
		data, err := serializeGob(info)
		if err != nil {
			return err
		}
		return b.Put([]byte("info"), data)
	})
}

// LoadNodeInfo reads node identity from disk
func (s *Store) LoadNodeInfo() (*NodeInfo, error) {
	var info *NodeInfo
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("node"))
		data := b.Get([]byte("info"))
		if data == nil {
			return nil
		}
		var v NodeInfo
		if err := deserializeGob(data, &v); err != nil {
			return err
		}
		info = &v
		return nil
	})
	return info, err
}

// ── Transaction Index ──

// SaveTxIndex stores a mapping from tx hash → {blockHeight, txIndex}
func (s *Store) SaveTxIndex(txHash [32]byte, height uint64, txIndex uint16) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("tx_index"))
		if err != nil {
			return err
		}
		var val [10]byte // 8 bytes height + 2 bytes index
		binary.BigEndian.PutUint64(val[:8], height)
		binary.BigEndian.PutUint16(val[8:10], txIndex)
		return b.Put(txHash[:], val[:])
	})
}

// LoadTxIndex looks up a tx hash and returns {height, txIndex}
func (s *Store) LoadTxIndex(txHash [32]byte) (height uint64, txIndex uint16, found bool, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tx_index"))
		if b == nil {
			return nil
		}
		val := b.Get(txHash[:])
		if val == nil || len(val) < 10 {
			return nil
		}
		height = binary.BigEndian.Uint64(val[:8])
		txIndex = binary.BigEndian.Uint16(val[8:10])
		found = true
		return nil
	})
	return
}

// ── Transaction Storage ──

// TxData is the on-disk format for a transaction
type TxData struct {
	Nonce    uint64
	From     string
	To       string
	Value    []byte // big.Int bytes
	GasLimit uint64
	GasPrice uint64
	Data     []byte
	Hash     [32]byte
	Signature []byte
}

// SaveBlockTxs stores all transactions in a block
func (s *Store) SaveBlockTxs(height uint64, txs []TxData) error {
	if len(txs) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("txs"))
		if err != nil {
			return err
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], height)
		data, err := serializeGob(txs)
		if err != nil {
			return err
		}
		return b.Put(buf[:], data)
	})
}

// LoadBlockTxs loads all transactions for a block
func (s *Store) LoadBlockTxs(height uint64) ([]TxData, error) {
	var txs []TxData
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("txs"))
		if b == nil {
			return nil
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], height)
		data := b.Get(buf[:])
		if data == nil {
			return nil
		}
		return deserializeGob(data, &txs)
	})
	return txs, err
}

// ── Serialization ──

func init() {
	gob.Register(&big.Int{})
}

// serializedAccount is the on-disk format for an EVM account
type serializedAccount struct {
	Nonce           uint64
	Balance         []byte // big.Int bytes
	CodeHash        [32]byte
	Code            []byte
	StorageKeys     [][32]byte
	StorageVals     [][32]byte
	ContractClass   uint8
	DoxDevLevel     uint8
	StateRentPaid   []byte
	LastRentPayment uint64
}

func serializeAccount(acc *evm.Account) ([]byte, error) {
	sa := serializedAccount{
		Nonce:           acc.Nonce,
		Balance:         acc.Balance.Bytes(),
		CodeHash:        acc.CodeHash,
		Code:            acc.Code,
		ContractClass:   uint8(acc.ContractClass),
		DoxDevLevel:     acc.DoxDevLevel,
		StateRentPaid:   acc.StateRentPaid.Bytes(),
		LastRentPayment: acc.LastRentPayment,
	}
	for k, v := range acc.Storage {
		sa.StorageKeys = append(sa.StorageKeys, k)
		sa.StorageVals = append(sa.StorageVals, v)
	}
	return serializeGob(sa)
}

func deserializeAccount(data []byte) (*evm.Account, error) {
	var sa serializedAccount
	if err := deserializeGob(data, &sa); err != nil {
		return nil, err
	}

	acc := evm.NewAccount()
	acc.Nonce = sa.Nonce
	acc.Balance.SetBytes(sa.Balance)
	acc.CodeHash = sa.CodeHash
	acc.Code = sa.Code
	acc.ContractClass = evm.ContractClass(sa.ContractClass)
	acc.DoxDevLevel = sa.DoxDevLevel
	acc.StateRentPaid.SetBytes(sa.StateRentPaid)
	acc.LastRentPayment = sa.LastRentPayment
	for i := range sa.StorageKeys {
		if i < len(sa.StorageVals) {
			acc.Storage[sa.StorageKeys[i]] = sa.StorageVals[i]
		}
	}
	return acc, nil
}

func serializeGob(v any) ([]byte, error) {
	var buf bytesBuffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func deserializeGob(data []byte, v any) error {
	buf := bytesBuffer{data: data}
	dec := gob.NewDecoder(&buf)
	return dec.Decode(v)
}

// Simple buffer that satisfies io.Writer/Reader for gob
type bytesBuffer struct {
	data []byte
	off  int
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, fmt.Errorf("eof")
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

func (b *bytesBuffer) Bytes() []byte { return b.data }
