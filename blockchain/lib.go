package blockchain

import (
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
		Sender: AddrFromKey(MinimalPk()),
		Payments: []Payment{
			Payment{Reciever: *addr, Amount: 0},
		},
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

// func SwitchName(name string, ownerPrivateKey *secp256k1.PrivateKey, newKey *secp256k1.PublicKey) t.Op {
// }

// func NewTxn(account *t.Account, accountPrivateKey *secp256k1.PrivateKey, reciever *t.Account, amount uint64) t.Op {
// }

// func Coinbase(account *t.Account, block *t.Block) t.Op {}
