package trsa

import "testing"

func TestOptimisticTRSA(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessSignature(n, i, NewOptimisticTRSACryptoHandler(1024),test)
	}
}

func TestOptimisticTRSANotEnoughShares(test *testing.T) {

	n := 10
	t := n/2 + 1

	testTRSANotEnoughShares(n,t, NewOptimisticTRSACryptoHandler(1024),test)
}

func TestOptimisticTRSASomeByzantineSignature(test *testing.T){
	testTRSASomeByzantineSignature(NewOptimisticTRSACryptoHandler(1024), test)
}

func TestOptimisticTRSAByzantineSignature(test *testing.T) {
	testTRSAByzantineSignature(NewOptimisticTRSACryptoHandler(1024), test)
}

