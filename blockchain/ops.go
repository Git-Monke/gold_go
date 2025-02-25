package blockchain

import (
	"encoding/binary"
	t "gold/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// Txn operation definition
type Txn struct {
	Sender    t.Address
	Payments  []Payment
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

	data = binary.LittleEndian.AppendUint32(data, uint32(t.Nonce))
	data = append(data, t.Signature.Serialize()...)

	return data
}

func (txn *Txn) PerformOp(state *t.State) t.UndoOp {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	senderKey := AddressToPk(&txn.Sender, &keyNameSet)

	for _, payment := range txn.Payments {
		recieverKey := AddressToPk(&payment.Reciever, &keyNameSet)

		if account, exists := accountSet[recieverKey]; exists {
			account.Balance += payment.Amount
		} else {
			accountSet[recieverKey] = &t.Account{Balance: payment.Amount, Nonce: 0}
		}

		accountSet[senderKey].Balance -= payment.Amount
		accountSet[senderKey].Nonce += 1
	}

	return &TxnUndo{
		Sender:   txn.Sender,
		Payments: txn.Payments,
	}
}

func (txn *TxnUndo) PerformUndo(state *t.State) {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	senderKey := AddressToPk(&txn.Sender, &keyNameSet)

	for _, payment := range txn.Payments {
		recieverKey := AddressToPk(&payment.Reciever, &keyNameSet)
		account := accountSet[recieverKey]

		if account.Balance == payment.Amount {
			delete(accountSet, recieverKey)
		} else {
			accountSet[recieverKey].Balance -= payment.Amount
		}

		accountSet[senderKey].Balance += payment.Amount
		accountSet[senderKey].Nonce -= 1
	}
}

func AddressToPk(ad *t.Address, keyNameSet *t.KeyNameSet) secp256k1.PublicKey {
	if ad.UsesName {
		return (*keyNameSet)[*ad.Name]
	}

	return *ad.Key
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
	Signature schnorr.Signature
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

	key, exists := keyNameSet[r.Name]

	// The fee is always paid by the old owner, if one exists.
	if exists {
		accountSet[key].Balance -= r.Fee
		accountSet[key].Nonce += 1
	} else {
		accountSet[*r.NewKey].Balance -= r.Fee
		accountSet[*r.NewKey].Nonce += 1
	}

	keyNameSet[r.Name] = *r.NewKey

	return &RenameUndo{
		Name:     r.Name,
		OldOwner: &key,
		Fee:      r.Fee,
	}
}

func (r *RenameUndo) PerformUndo(state *t.State) {
	accountSet := state.AccountSet
	keyNameSet := state.KeyNameSet

	currOwner, _ := keyNameSet[r.Name]

	// If there was a previous owner, reimburse them. Otherwise, reimburse the current owner.
	if r.OldOwner != nil {
		accountSet[*r.OldOwner].Balance += r.Fee
		accountSet[*r.OldOwner].Nonce -= 1
		keyNameSet[r.Name] = *r.OldOwner
	} else {
		accountSet[currOwner].Balance += r.Fee
		accountSet[currOwner].Nonce -= 1
		// If there was no previous owner, remove the name from the hashmap set
		delete(keyNameSet, r.Name)
	}
}
