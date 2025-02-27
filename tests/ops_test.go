package tests

import (
	"gold/blockchain"
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
	state.KeyNameSet[name] = key
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
		Signature: b.MinimalSignature(),
	}

	rename.PerformOp(&state)

	if state.AccountSet[pubKeyMonke].Balance != 100_000_000_000 {
		t.Errorf("Fee was paid incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 1 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 1)
	}

	if *state.KeyNameSet["GitMonke"] != pubKeyJeff {
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
		Signature: b.MinimalSignature(),
	}

	renameUndo := rename.PerformOp(&state)
	renameUndo.PerformUndo(&state)

	if state.AccountSet[pubKeyMonke].Balance != 200_000_000_000 {
		t.Errorf("Fee was reimbursed incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 0 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 0)
	}

	if *state.KeyNameSet["GitMonke"] != pubKeyMonke {
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
		Signature: b.MinimalSignature(),
	}

	rename.PerformOp(&state)

	if state.AccountSet[pubKeyMonke].Balance != 100_000_000_000 {
		t.Errorf("Fee was paid incorrectly, GitMonke has %d wanted %d", state.AccountSet[pubKeyMonke].Balance, 100_000_000_000)
	}

	if state.AccountSet[pubKeyMonke].Nonce != 1 {
		t.Errorf("GitMonke nonce was incorrect, got %d wanted %d", state.AccountSet[pubKeyMonke].Nonce, 1)
	}

	if *state.KeyNameSet["GitMonke"] != pubKeyMonke {
		t.Errorf("Name was transferred improperly")
	}
}

func TestNameNotInSet(t *testing.T) {
	state := initState()
	addr := b.AddrFromName("GitMonke")

	if b.AddressToPk(&addr, &state.KeyNameSet) != nil {
		t.Error("This function should return nil without breaking")
	}
}

func TestValidateTxn(t *testing.T) {
	state, txn, _ := createValidTxn()
	error := txn.Validate(&state)

	if error != nil {
		t.Error(error.Error())
	}
}

func TestInvalidTxns(t *testing.T) {
	state, txn, sk := createValidTxn()
	txn.Fee = 100_000_000_001
	txn.Signature = txn.Sign(&sk)
	error := txn.Validate(&state)

	if !(error != nil && error.Error() == "txn sends more than senders balance") {
		t.Errorf("Expected error due to overspending, got %v", error)
	}

	state, txn, sk = createValidTxn()
	txn.Sender = b.AddrFromName("Balls")
	error = txn.Validate(&state)

	if !(error != nil && error.Error() == "sender address does not exist") {
		t.Errorf("Expected error due to nonexistent address, got %v", error.Error())
	}

	state, txn, sk = createValidTxn()
	txn.Fee = 1
	error = txn.Validate(&state)

	if !(error != nil && error.Error() == "txn sig is incorrect") {
		t.Errorf("Expected error due to nonexistent address, got %v", error.Error())
	}

	state, txn, sk = createValidTxn()
	txn.Nonce = 1
	txn.Signature = txn.Sign(&sk)
	error = txn.Validate(&state)

	if !(error != nil && error.Error() == "txn uses the wrong nonce") {
		t.Errorf("Expected error due to nonexistent address, got %v", error.Error())
	}

}

func createValidTxn() (types.State, b.Txn, secp256k1.PrivateKey) {
	state := initState()
	privKeyMonke, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	txn := b.Txn{
		Sender:    b.AddrFromName("GitMonke"),
		Payments:  []b.Payment{{Reciever: b.AddrFromKey(&pubKeyJeff), Amount: 100_000_000_000}},
		Signature: b.MinimalSignature(),
	}

	txn.Signature = txn.Sign(&privKeyMonke)

	return state, txn, privKeyMonke
}

func createValidRename() (types.State, b.Rename, secp256k1.PrivateKey, secp256k1.PublicKey) {
	state := initState()
	privKeyMonke, pubKeyMonke := newKeypair()
	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	_, pubKeyJeff := newKeypair()

	txn := b.Rename{
		Name:   "GitMonke",
		NewKey: &pubKeyJeff,
		Fee:    100_000_000_000,
		Nonce:  0,
	}

	txn.Signature = txn.Sign(&privKeyMonke)

	return state, txn, privKeyMonke, pubKeyMonke
}

func TestValidRename(t *testing.T) {
	state, rename, monkePrivKey, monkePubKey := createValidRename()
	error := rename.Validate(&state)
	if error != nil {
		t.Errorf("Expected no error, got %v", error)
	}

	state, rename, monkePrivKey, monkePubKey = createValidRename()
	delete(state.KeyNameSet, "GitMonke")
	rename.NewKey = &monkePubKey
	rename.Signature = rename.Sign(&monkePrivKey)
	error = rename.Validate(&state)
	if error != nil {
		t.Errorf("Expected no error, got %v", error)
	}
}

func TestInvalidRenames(t *testing.T) {
	// Check liable parties exist and have the right amount
	state, rename, monkePrivKey, monkePubKey := createValidRename()
	delete(state.KeyNameSet, "GitMonke")
	rename.Signature = rename.Sign(&monkePrivKey)
	error := rename.Validate(&state)

	if !(error != nil && error.Error() == "The liable key-holder is not in the account set") {
		t.Errorf("Expected missing key-holder error, got %v", error)
	}

	state, rename, monkePrivKey, monkePubKey = createValidRename()
	delete(state.AccountSet, monkePubKey)
	rename.Signature = rename.Sign(&monkePrivKey)
	error = rename.Validate(&state)

	if !(error != nil && error.Error() == "The liable key-holder is not in the account set") {
		t.Errorf("Expected missing key-holder error, got %v", error)
	}

	// Check liable parties exist and have the right amount
	state, rename, monkePrivKey, monkePubKey = createValidRename()
	state.AccountSet[monkePubKey].Balance = 50_000_000
	rename.Signature = rename.Sign(&monkePrivKey)
	error = rename.Validate(&state)

	if !(error != nil && error.Error() == "The liable key-holder cannot pay the fee") {
		t.Errorf("Expected missing key-holder error, got %v", error)
	}

	state, rename, monkePrivKey, monkePubKey = createValidRename()
	delete(state.KeyNameSet, "GitMonke")
	rename.NewKey = &monkePubKey
	state.AccountSet[monkePubKey].Balance = 50_000_000
	rename.Signature = rename.Sign(&monkePrivKey)
	error = rename.Validate(&state)

	if !(error != nil && error.Error() == "The liable key-holder cannot pay the fee") {
		t.Errorf("Expected missing key-holder error, got %v", error)
	}

	state, rename, monkePrivKey, monkePubKey = createValidRename()
	rename.Fee += 1
	error = rename.Validate(&state)
	if !(error != nil && error.Error() == "sig is invalid") {
		t.Errorf("Expected no error, got %v", error)
	}
}

func TestValidation(t *testing.T) {
	state := types.State{
		AccountSet: make(types.AccountSet),
		KeyNameSet: make(types.KeyNameSet),
		BlockSizes: [100]int{},
		Timestamps: [720]uint64{},
		Height:     0,
	}

	privKeyMonke, pubKeyMonke := newKeypair()
	_, pubKeyJeff := newKeypair()

	initAccount(&state, "GitMonke", &pubKeyMonke, 200_000_000_000)
	initAccount(&state, "Jeff", &pubKeyJeff, 0)

	monkeAddr := b.AddrFromName("GitMonke")
	jeffAddr := b.AddrFromName("Jeff")

	// Once these operations are performed, GitMonke should have 200_000_000_000 (from the coinbase), Jeff should have 200_000_000_000, and Jeff should own the "GitMonke" name
	ops := []types.Op{
		b.TemplateCoinbase(&monkeAddr),
		b.NewRename("GitMonke", &privKeyMonke, &pubKeyJeff),
		b.NewTxn(&monkeAddr, privKeyMonke, &jeffAddr, 200_000_000_000),
	}

	header := types.Header{
		PrevBlockHash: b.HashBlockHeader(blockchain.GenesisHeader()),
		MerkleRoot:    b.CalculateMerkleRoot(ops),
		Timestamp:     1,
		Nonce:         0,
	}

	block := types.Block{
		Header:     header,
		Operations: ops,
	}

	block.Operations[0] = b.Coinbase(&monkeAddr, &block)

	if b.ValidateBlock(&block, &state) != true {
		t.Error("Block did not validate properly")
	}
}
