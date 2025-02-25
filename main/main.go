package main

import (
	"fmt"
	b "gold/blockchain"
)

func main() {
	minimalPk := b.MinimalPk()
	minimalSig := b.MinimalSignature()

	txn := b.Txn{
		Sender:    b.AddrFromName("GitMonke"),
		Payments:  []b.Payment{{Reciever: b.AddrFromKey(minimalPk), Amount: 100_000_000_000}},
		Nonce:     0,
		Signature: minimalSig,
	}

	fmt.Println(txn.Encode())
}
