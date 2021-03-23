package tbls

import (
	"testing"
)

func TestTBLSOptimistic(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessSignature(n, i, NewTBLS256OptimisticCryptoHandler(),test)
	}
}

func TestTBLSOptimisticNotEnouthShares(test *testing.T) {
	notEnoughShares(NewTBLS256OptimisticCryptoHandler(),test)
}

func TestTBLSOptimisticLessThanTByzantineSignature(test *testing.T) {
	tblsHalfByzantineSignature(NewTBLS256OptimisticCryptoHandler() ,test)
}
