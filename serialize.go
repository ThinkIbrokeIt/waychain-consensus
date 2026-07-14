package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ThinkIbrokeIt/waychain-consensus/evm"
)

// ── Binary Wire Format for Transaction ──
//
// Transactions are serialized to binary (then hex-wrapped for RPC).
// Fields in order:
//
//   nonce:       uint64 big-endian (8 bytes)
//   fromLen:     uint16 big-endian (2 bytes)
//   from:        UTF-8 string (fromLen bytes) — hex-encoded public key
//   toLen:       uint16 big-endian (2 bytes)
//   to:          UTF-8 string (toLen bytes) — hex address or empty
//   valueLen:    uint16 big-endian (2 bytes)
//   value:       big.Int bytes (valueLen bytes)
//   gasLimit:    uint64 big-endian (8 bytes)
//   gasPrice:    uint64 big-endian (8 bytes)
//   lane:        uint8 (1 byte) — execution lane (0=consensus, 1=oracle, 2=private)
//   encDataLen:  uint32 big-endian (4 bytes) — encrypted data length
//   encData:     raw bytes (encDataLen bytes) — encrypted payload for private lanes
//   dataLen:     uint32 big-endian (4 bytes)
//   data:        raw bytes (dataLen bytes)
//   sigLen:      uint16 big-endian (2 bytes)
//   signature:   raw bytes (sigLen bytes)
//
// The tx Hash is NOT on the wire — it is computed by the receiver
// as SHA256(nonce + from + to + value + gasLimit + lane + data).
// The signature covers tx.Hash.

// SerializeTx serializes a Transaction (including signature) to binary.
func SerializeTx(tx *Transaction) []byte {
	valBytes := tx.Value.Bytes()
	var buf []byte

	buf = append(buf, u64be(tx.Nonce)...)           // nonce
	buf = append(buf, u16be(uint16(len(tx.From)))...) // fromLen
	buf = append(buf, []byte(tx.From)...)            // from
	buf = append(buf, u16be(uint16(len(tx.To)))...)   // toLen
	buf = append(buf, []byte(tx.To)...)               // to
	buf = append(buf, u16be(uint16(len(valBytes)))...) // valueLen
	buf = append(buf, valBytes...)                     // value
	buf = append(buf, u64be(tx.GasLimit)...)           // gasLimit
	buf = append(buf, u64be(tx.GasPrice)...)           // gasPrice
	buf = append(buf, byte(tx.Lane))                  // lane (1 byte)
	buf = append(buf, u32be(uint32(len(tx.EncryptedData)))...) // encDataLen
	buf = append(buf, tx.EncryptedData...)                     // encrypted data
	buf = append(buf, u32be(uint32(len(tx.Data)))...)  // dataLen
	buf = append(buf, tx.Data...)                      // data
	buf = append(buf, u16be(uint16(len(tx.Signature)))...) // sigLen
	buf = append(buf, tx.Signature...)                     // signature

	return buf
}

// DeserializeTx deserializes a Transaction from binary.
func DeserializeTx(data []byte) (*Transaction, error) {
	tx := &Transaction{
		Value:   new(big.Int),
	}

	r := &reader{data: data}

	// nonce
	if !r.read(8) { return nil, fmt.Errorf("tx: short read for nonce") }
	tx.Nonce = be64(r.buf)

	// from
	if !r.read(2) { return nil, fmt.Errorf("tx: short read for fromLen") }
	fromLen := be16(r.buf)
	if !r.read(int(fromLen)) { return nil, fmt.Errorf("tx: short read for from") }
	tx.From = string(r.buf)

	// to
	if !r.read(2) { return nil, fmt.Errorf("tx: short read for toLen") }
	toLen := be16(r.buf)
	if !r.read(int(toLen)) { return nil, fmt.Errorf("tx: short read for to") }
	tx.To = string(r.buf)

	// value
	if !r.read(2) { return nil, fmt.Errorf("tx: short read for valueLen") }
	valLen := be16(r.buf)
	if !r.read(int(valLen)) { return nil, fmt.Errorf("tx: short read for value") }
	tx.Value.SetBytes(r.buf)

	// gasLimit
	if !r.read(8) { return nil, fmt.Errorf("tx: short read for gasLimit") }
	tx.GasLimit = be64(r.buf)

	// gasPrice
	if !r.read(8) { return nil, fmt.Errorf("tx: short read for gasPrice") }
	tx.GasPrice = be64(r.buf)

	// lane
	if !r.read(1) { return nil, fmt.Errorf("tx: short read for lane") }
	tx.Lane = evm.LaneType(r.buf[0])

	// encrypted data
	if !r.read(4) { return nil, fmt.Errorf("tx: short read for encDataLen") }
	encDataLen := be32(r.buf)
	if !r.read(int(encDataLen)) { return nil, fmt.Errorf("tx: short read for encrypted data") }
	tx.EncryptedData = make([]byte, encDataLen)
	copy(tx.EncryptedData, r.buf)

	// data
	if !r.read(4) { return nil, fmt.Errorf("tx: short read for dataLen") }
	dataLen := be32(r.buf)
	if !r.read(int(dataLen)) { return nil, fmt.Errorf("tx: short read for data") }
	tx.Data = make([]byte, dataLen)
	copy(tx.Data, r.buf)

	// signature
	if !r.read(2) { return nil, fmt.Errorf("tx: short read for sigLen") }
	sigLen := be16(r.buf)
	if !r.read(int(sigLen)) { return nil, fmt.Errorf("tx: short read for signature") }
	tx.Signature = make([]byte, sigLen)
	copy(tx.Signature, r.buf)

	// Compute hash from fields (hash excludes signature, includes lane and encryptedData)
		hashInput := fmt.Sprintf("%d:%s:%s:%s:%d:%d:%d:%x:%x",
			tx.Nonce, tx.From, tx.To, tx.Value.String(), tx.GasLimit, tx.Lane, len(tx.Data), tx.Data, tx.EncryptedData)
		tx.Hash = sha256.Sum256([]byte(hashInput))

	return tx, nil
}

// SerializeTxHex returns the hex-encoded serialized transaction.
func SerializeTxHex(tx *Transaction) string {
	return hex.EncodeToString(SerializeTx(tx))
}

// DeserializeTxHex deserializes a hex-encoded binary transaction.
func DeserializeTxHex(hexStr string) (*Transaction, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("tx: hex decode: %w", err)
	}
	return DeserializeTx(data)
}

// ── Binary helpers ──

func u64be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func u32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func u16be(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func be64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b[:8])
}

func be32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b[:4])
}

func be16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b[:2])
}

type reader struct {
	data []byte
	off  int
	buf  []byte
}

func (r *reader) read(n int) bool {
	if r.off+n > len(r.data) {
		return false
	}
	r.buf = r.data[r.off : r.off+n]
	r.off += n
	return true
}

// TxJSON is a JSON-serializable representation of a Transaction
// for use in RPC responses.
type TxJSON struct {
	Nonce       string `json:"nonce"`
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	GasLimit    string `json:"gasLimit"`
	GasPrice    string `json:"gasPrice"`
	Data        string `json:"data"`
	Hash        string `json:"hash"`
	Signature   string `json:"signature"`
	Lane        string `json:"lane"`        // Added: execution lane
	EncryptedData string `json:"encryptedData,omitempty"` // Added: encrypted payload
}

// ToJSON converts a Transaction to its JSON representation.
func (tx *Transaction) ToJSON() TxJSON {
	return TxJSON{
		Nonce:       fmt.Sprintf("0x%x", tx.Nonce),
		From:        "0x" + tx.From,
		To:          "0x" + tx.To,
		Value:       "0x" + tx.Value.Text(16),
		GasLimit:    fmt.Sprintf("0x%x", tx.GasLimit),
		GasPrice:    fmt.Sprintf("0x%x", tx.GasPrice),
		Data:        "0x" + hex.EncodeToString(tx.Data),
		Hash:        "0x" + hex.EncodeToString(tx.Hash[:]),
		Signature:   "0x" + hex.EncodeToString(tx.Signature),
		Lane:        fmt.Sprintf("0x%d", tx.Lane),
		EncryptedData: hex.EncodeToString(tx.EncryptedData),
	}
}