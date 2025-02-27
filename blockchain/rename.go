package blockchain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	t "gold/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// Rename operation definition
type Rename struct {
	Name      string
	NewKey    *secp256k1.PublicKey
	Fee       uint64
	Nonce     uint32
	Signature *schnorr.Signature
}

type RenameUndo struct {
	Name     string
	OldOwner *secp256k1.PublicKey
	Fee      uint64
}

func (r *Rename) Encode() []byte {
	data := []byte{1}

	data = append(data, byte(len([]byte(r.Name))))
	data = append(data, []byte(r.Name)...)

	data = append(data, r.NewKey.SerializeCompressed()...)

	data = binary.LittleEndian.AppendUint64(data, r.Fee)
	data = binary.LittleEndian.AppendUint32(data, r.Nonce)

	data = append(data, r.Signature.Serialize()...)

	return data
}

func (r *Rename) PerformOp(state *t.State) t.UndoOp {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	keyPtr, exists := keyNameSet[r.Name]

	// The fee is always paid by the old owner, if one exists.
	if exists {
		key := *keyPtr
		accountSet[key].Balance -= r.Fee
		accountSet[key].Nonce += 1
	} else {
		accountSet[*r.NewKey].Balance -= r.Fee
		accountSet[*r.NewKey].Nonce += 1
	}

	keyNameSet[r.Name] = r.NewKey

	return &RenameUndo{
		Name:     r.Name,
		OldOwner: keyPtr,
		Fee:      r.Fee,
	}
}

// Todo
func (r *Rename) Validate(state *t.State) error {
	// Check the nonce matches whoever is signing
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	currOwner, nameExists := keyNameSet[r.Name]
	var payingKey *secp256k1.PublicKey

	// The key used to index the accountSet can be factored out
	if !nameExists {
		payingKey = r.NewKey
	} else {
		payingKey = currOwner
	}

	account, newKeyExists := accountSet[*payingKey]

	if !newKeyExists {
		return errors.New("The liable key-holder is not in the account set")
	}

	if account.Balance < r.Fee {
		return errors.New("The liable key-holder cannot pay the fee")
	}

	if !r.CheckSig(r.Signature, payingKey) {
		return errors.New("sig is invalid")
	}

	return nil
}

func (r Rename) Sign(privKey *secp256k1.PrivateKey) *schnorr.Signature {
	r.Signature = MinimalSignature()
	hash := sha256.Sum256(r.Encode())
	sig, _ := schnorr.Sign(privKey, hash[:])
	return sig
}

func (r Rename) CheckSig(sig *schnorr.Signature, pubKey *secp256k1.PublicKey) bool {
	r.Signature = MinimalSignature()
	hash := sha256.Sum256(r.Encode())
	return sig.Verify(hash[:], pubKey)
}

func (r *RenameUndo) PerformUndo(state *t.State) {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	currOwnerPtr, _ := keyNameSet[r.Name]
	currOwner := *currOwnerPtr

	// If there was a previous owner, reimburse them. Otherwise, reimburse the current owner.
	if r.OldOwner != nil {
		accountSet[*r.OldOwner].Balance += r.Fee
		accountSet[*r.OldOwner].Nonce -= 1
		keyNameSet[r.Name] = r.OldOwner
	} else {
		accountSet[currOwner].Balance += r.Fee
		accountSet[currOwner].Nonce -= 1
		// If there was no previous owner, remove the name from the hashmap set
		delete(keyNameSet, r.Name)
	}
}
