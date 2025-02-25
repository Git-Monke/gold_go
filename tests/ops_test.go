package tests

import (
	b "gold/blockchain"
	"gold/types"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func newKeypair() (secp256k1.PrivateKey, secp256k1.PublicKey) {
	privKey, _ := secp256k1.GeneratePrivateKey()
	return *privKey, *privKey.PubKey()
}

func initAccount(state *types.State, name string, key *secp256k1.PublicKey, balance uint64) {
	state.AccountSet[*key] = &types.Account{
		Balance: balance,
		Nonce:   0,
	}
	state.KeyNameSet[name] = *key
}

func initState() types.State {
	return types.State{
		AccountSet: make(types.AccountSet),
		KeyNameSet: make(types.KeyNameSet),
		BlockSizes: [100]int{},
		Timestamps: [720]uint64{},
		Height:     0,
	}
}

func TestPerformTxn(t *testing.T) {
	state := initState()
	_, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	txn := b.Txn{
		Sender:    b.AddrFromName("GitMonke"),
		Payments:  []b.Payment{{Reciever: b.AddrFromKey(&pubKeyJeff), Amount: 100_000_000_000}},
		Nonce:     0,
		Signature: b.MinimalSignature(),
	}

	txn.PerformOp(&state)

	if state.AccountSet[pubKeyMonke].Balance != 100_000_000_000 {
		t.Errorf("GitMonke balance was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyJeff].Balance != 100_000_000_000 {
		t.Errorf("GitMonke balance was incorrect, got %d wanted %d", state.AccountSet[pubKeyJeff].Balance, 1)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 1 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 1)
	}
}

func TestPerformUndoTxn(t *testing.T) {
	state := initState()
	_, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	txn := b.Txn{
		Sender:    b.AddrFromName("GitMonke"),
		Payments:  []b.Payment{{Reciever: b.AddrFromKey(&pubKeyJeff), Amount: 100_000_000_000}},
		Nonce:     0,
		Signature: b.MinimalSignature(),
	}

	undoOp := txn.PerformOp(&state)
	undoOp.PerformUndo(&state)

	if state.AccountSet[pubKeyMonke].Balance != 200_000_000_000 {
		t.Errorf("GitMonke balance was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 200_000_000_000)
	}

	_, exists := state.AccountSet[pubKeyJeff]
	if exists {
		t.Errorf("Jeff was not removed from the account set")
	}

	if state.AccountSet[pubKeyMonke].Nonce != 0 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 0)
	}
}

func TestPerformRename(t *testing.T) {
	state := initState()
	_, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	rename := b.Rename{
		Name:      "GitMonke",
		NewKey:    &pubKeyJeff,
		Fee:       100_000_000_000,
		Nonce:     0,
		Signature: *b.MinimalSignature(),
	}

	rename.PerformOp(&state)

	if state.AccountSet[pubKeyMonke].Balance != 100_000_000_000 {
		t.Errorf("Fee was paid incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 1 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 1)
	}

	if state.KeyNameSet["GitMonke"] != pubKeyJeff {
		t.Errorf("Name was not transferred to Jeff's public key")
	}
}

func TestUndoRename(t *testing.T) {
	state := initState()
	_, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	rename := b.Rename{
		Name:      "GitMonke",
		NewKey:    &pubKeyJeff,
		Fee:       100_000_000_000,
		Nonce:     0,
		Signature: *b.MinimalSignature(),
	}

	renameUndo := rename.PerformOp(&state)
	renameUndo.PerformUndo(&state)

	if state.AccountSet[pubKeyMonke].Balance != 200_000_000_000 {
		t.Errorf("Fee was reimbursed incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 0 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 0)
	}

	if state.KeyNameSet["GitMonke"] != pubKeyMonke {
		t.Errorf("Name was not moved back to GitMonke's public key")
	}
}

func TestNewName(t *testing.T) {
	state := initState()
	_, pubKeyMonke := newKeypair()
	state.AccountSet[pubKeyMonke] = &types.Account{
		Balance: 200_000_000_000,
		Nonce:   0,
	}

	rename := b.Rename{
		Name:      "GitMonke",
		NewKey:    &pubKeyMonke,
		Fee:       100_000_000_000,
		Nonce:     0,
		Signature: *b.MinimalSignature(),
	}

	rename.PerformOp(&state)

	if state.AccountSet[pubKeyMonke].Balance != 100_000_000_000 {
		t.Errorf("Fee was paid incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 1 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 1)
	}

	if state.KeyNameSet["GitMonke"] != pubKeyMonke {
		t.Errorf("Name was transferred improperly")
	}
}

// func TestValidation(t *testing.T) {
// 	state := types.State{
// 		AccountSet: make(types.AccountSet),
// 		KeyNameSet: make(types.KeyNameSet),
// 		BlockSizes: [100]int{},
// 		Timestamps: [720]uint64{},
// 		Height:     0,
// 	}

// 	privKeyMonke, pubKeyMonke := newKeypair()
// 	_, pubKeyJeff := newKeypair()

// 	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
// 	initAccount(&state, "Jeff", &pubKeyJeff, 0)

// 	monkeAddr := b.AddrFromName("GitMonke")
// 	jeffAddr := b.AddrFromName("Jeff")

// 	// Once these operations are performed, GitMonke should have 200_000_000_000 (from the coinbase), Jeff should have 200_000_000_000, and Jeff should own the "GitMonke" name
// 	ops := []types.Op{
// 		b.TemplateCoinbase(&monkeAddr),
// 		b.SwitchName("GitMonke", &privKeyMonke, &pubKeyJeff),
// 		b.NewTxn(&monkeAddr, privKeyMonke, &jeffAddr, 200_000_000_000),
// 	}

// 	header := types.Header{
// 		PrevBlockHash: b.HashBlockHeader(blockchain.GenesisHeader()),
// 		MerkleRoot:    b.CalculateMerkleRoot(ops),
// 		Timestamp:     1,
// 		Nonce:         0,
// 	}

// 	block := types.Block{
// 		Header:     header,
// 		Operations: ops,
// 	}

// 	block.Operations[0] = b.Coinbase(&monkeAddr, &block)

// 	if b.ValidateBlock(&block, &state) != true {
// 		t.Error("Block did not validate properly")
// 	}
// }
