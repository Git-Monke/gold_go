package types

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Blockchain

type Block struct {
	Header     Header
	Operations []Op
}

type Header struct {
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     uint64
	Nonce         uint64
}

// State Management

type AccountSet = map[secp256k1.PublicKey]*Account
type KeyNameSet = map[string]secp256k1.PublicKey

type State struct {
	AccountSet AccountSet
	KeyNameSet KeyNameSet
	BlockSizes [100]int
	Timestamps [720]uint64
	Height     int
}

type Account struct {
	Balance uint64
	Nonce   int
}

// Blockchain Operations

type Op interface {
	Encode() []byte
	PerformOp(state *State) UndoOp
	// Validate(state *State) bool
}

type UndoOp interface {
	PerformUndo(state *State)
}

// --
type Address struct {
	UsesName bool
	Name     *string
	Key      *secp256k1.PublicKey
}
