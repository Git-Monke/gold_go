package blockchain

import (
	"crypto/sha256"
	"encoding/binary"
	"gold/types"
	t "gold/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

func GenesisHeader() t.Header {
	return t.Header{
		PrevBlockHash: [32]byte{},
		MerkleRoot:    [32]byte{},
		Timestamp:     0,
		Nonce:         0,
	}
}

func HashBlockHeader(header types.Header) [32]byte {
	return sha256.Sum256(EncodeHeader(header))
}

func EncodeHeader(header t.Header) []byte {
	data := make([]byte, 0)

	data = append(data, header.PrevBlockHash[:]...)
	data = append(data, header.MerkleRoot[:]...)
	data = binary.LittleEndian.AppendUint32(data, header.Timestamp)
	data = binary.LittleEndian.AppendUint64(data, header.Nonce)

	return data
}

func AddrFromName(name string) t.Address {
	return t.Address{
		UsesName: true,
		Name:     &name,
		Key:      nil,
	}
}

func AddrFromKey(key *secp256k1.PublicKey) t.Address {
	return t.Address{
		UsesName: false,
		Name:     nil,
		Key:      key,
	}
}

// Template coinbase has all the values except the amount. It's used for calculating the final block size when determining coinbase penalties.
func TemplateCoinbase(addr *t.Address) t.Op {
	return &Txn{
		Sender:    AddrFromKey(MinimalPk()),
		Payments:  []Payment{{Reciever: *addr, Amount: 0}},
		Nonce:     0,
		Signature: MinimalSignature(),
	}
}

func MinimalSignature() *schnorr.Signature {
	sig, _ := schnorr.ParseSignature(make([]byte, 64))
	return sig
}

func MinimalPk() *secp256k1.PublicKey {
	return secp256k1.NewPublicKey(&secp256k1.FieldVal{}, &secp256k1.FieldVal{})
}

func NewRename(name string, ownerPrivKey *secp256k1.PrivateKey, newKey *secp256k1.PublicKey) t.Op {
	op := &Rename{
		Name:   name,
		NewKey: newKey,
		Fee:    0,
		Nonce:  0,
	}

	op.Signature = op.Sign(ownerPrivKey)

	return op
}

func NewTxn(senderAddr t.Address, senderPrivKey *secp256k1.PrivateKey, recieverAddr *t.Address, amount uint64, fee uint64) *Txn {
	op := Txn{
		Sender:   senderAddr,
		Payments: []Payment{{Reciever: *recieverAddr, Amount: amount}},
		Fee:      fee,
		Nonce:    0,
	}

	op.Signature = op.Sign(senderPrivKey)

	return &op
}

// func NewTxn(account *t.Account, accountPrivateKey *secp256k1.PrivateKey, reciever *t.Account, amount uint64) t.Op {
// }

// func Coinbase(account *t.Account, block *t.Block) t.Op {}
