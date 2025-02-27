package blockchain

import (
	t "gold/types"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// If the address uses a name not in the set, it will return a nil pointer
func AddressToPk(ad *t.Address, keyNameSet *t.KeyNameSet) *secp256k1.PublicKey {
	if ad.UsesName {
		return (*keyNameSet)[*ad.Name]
	}

	return ad.Key
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
