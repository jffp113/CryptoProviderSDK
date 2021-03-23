package tbls

import (
	"testing"
)

func TestTBLSPessimistic(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessSignature(n, i, NewTBLS256PessimisticCryptoHandler(),test)
	}
}

func TestTBLSPessimisticNotEnouthShares(test *testing.T) {
	notEnoughShares(NewTBLS256PessimisticCryptoHandler(),test)
}

func TestTBLSPessimisticLessThanTByzantineSignature(test *testing.T) {
	tblsHalfByzantineSignature(NewTBLS256PessimisticCryptoHandler() ,test)
}
