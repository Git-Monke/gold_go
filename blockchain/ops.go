package blockchain

import (
	"encoding/binary"
	"errors"
	t "gold/types"

	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// Txn operation definition
type Txn struct {
	Sender    t.Address
	Payments  []Payment
	Fee       uint64
	Nonce     uint32
	Signature *schnorr.Signature
}

type Payment struct {
	Reciever t.Address
	Amount   uint64
}

type TxnUndo struct {
	Sender   t.Address
	Payments []Payment
}

func (t *Txn) Encode() []byte {
	// 0 flag = Txn. 1 flag = Rename
	data := []byte{0}

	data = encodeAddress(&t.Sender, data)
	data = append(data, byte(len(t.Payments)))

	for _, payment := range t.Payments {
		data = encodePayment(payment, data)
	}

	data = binary.LittleEndian.AppendUint64(data, t.Fee)
	data = binary.LittleEndian.AppendUint32(data, t.Nonce)

	data = append(data, t.Signature.Serialize()...)

	return data
}

func (txn *Txn) PerformOp(state *t.State) t.UndoOp {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	senderKey := AddressToPk(&txn.Sender, &keyNameSet)

	for _, payment := range txn.Payments {
		recieverKey := AddressToPk(&payment.Reciever, &keyNameSet)

		if account, exists := accountSet[*recieverKey]; exists {
			account.Balance += payment.Amount
		} else {
			accountSet[*recieverKey] = &t.Account{Balance: payment.Amount, Nonce: 0}
		}

		accountSet[*senderKey].Balance -= payment.Amount
		accountSet[*senderKey].Nonce += 1
	}

	return &TxnUndo{
		Sender:   txn.Sender,
		Payments: txn.Payments,
	}
}

func (txn Txn) Validate(state *t.State) error {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	senderPkPtr := AddressToPk(&txn.Sender, &keyNameSet)

	if senderPkPtr == nil {
		return errors.New("sender address does not exist")
	}

	senderPk := *senderPkPtr

	var totalSent uint64 = 0
	account := accountSet[senderPk]

	for _, payment := range txn.Payments {
		totalSent += payment.Amount
	}

	if totalSent+txn.Fee > account.Balance {
		return errors.New("txn sends more than senders balance")
	}

	if account.Nonce != txn.Nonce {
		return errors.New("txn uses the wrong nonce")
	}

	if !txn.CheckSig(txn.Signature, &senderPk) {
		return errors.New("txn sig is incorrect")
	}

	return nil
}

func (txn Txn) Sign(privKey *secp256k1.PrivateKey) *schnorr.Signature {
	txn.Signature = MinimalSignature()
	hash := sha256.Sum256(txn.Encode())
	sig, _ := schnorr.Sign(privKey, hash[:])
	return sig
}

func (txn Txn) CheckSig(sig *schnorr.Signature, pubKey *secp256k1.PublicKey) bool {
	txn.Signature = MinimalSignature()
	hash := sha256.Sum256(txn.Encode())
	return sig.Verify(hash[:], pubKey)
}

func (txn *TxnUndo) PerformUndo(state *t.State) {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	senderKey := AddressToPk(&txn.Sender, &keyNameSet)

	for _, payment := range txn.Payments {
		recieverKey := *AddressToPk(&payment.Reciever, &keyNameSet)
		account := accountSet[recieverKey]

		if account.Balance == payment.Amount {
			delete(accountSet, recieverKey)
		} else {
			accountSet[recieverKey].Balance -= payment.Amount
		}

		accountSet[*senderKey].Balance += payment.Amount
		accountSet[*senderKey].Nonce -= 1
	}
}

// If the address uses a name not in the set, it will return a nil pointer
func AddressToPk(ad *t.Address, keyNameSet *t.KeyNameSet) *secp256k1.PublicKey {
	if ad.UsesName {
		return (*keyNameSet)[*ad.Name]
	}

	return ad.Key
}

func encodePayment(payment Payment, data []byte) []byte {
	data = encodeAddress(&payment.Reciever, data)
	data = binary.LittleEndian.AppendUint64(data, payment.Amount)
	return data
}

func encodeAddress(addr *t.Address, data []byte) []byte {
	if addr.UsesName {
		data = append(data, 1)
		// Append the # of bytes the name is
		data = append(data, byte(len([]byte(*addr.Name))))
		data = append(data, []byte(*addr.Name)...)
	} else {
		data = append(data, 0)
		data = append(data, addr.Key.SerializeCompressed()...)
	}

	return data
}

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
