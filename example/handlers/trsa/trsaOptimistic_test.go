package trsa

import "testing"

func TestOptimisticTRSA(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessSignature(n, i, NewOptimisticTRSACryptoHandler(),test)
	}
}

func TestOptimisticTRSANotEnoughShares(test *testing.T) {

	n := 10
	t := n/2 + 1

	testTRSANotEnoughShares(n,t, NewOptimisticTRSACryptoHandler(),test)
}

func TestOptimisticTRSASomeByzantineSignature(test *testing.T){
	testTRSASomeByzantineSignature(NewOptimisticTRSACryptoHandler(), test)
}

func TestOptimisticTRSAByzantineSignature(test *testing.T) {
	testTRSAByzantineSignature(NewOptimisticTRSACryptoHandler(), test)
}

