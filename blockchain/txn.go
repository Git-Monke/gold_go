package blockchain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	t "gold/types"

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

func encodePayment(payment Payment, data []byte) []byte {
	data = encodeAddress(&payment.Reciever, data)
	data = binary.LittleEndian.AppendUint64(data, payment.Amount)
	return data
}
