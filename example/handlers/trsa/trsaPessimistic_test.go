package trsa

import "testing"

func TestPessimisticTRSA(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessSignature(n, i, NewPessimisticTRSACryptoHandler(),test)
	}
}

func TestPessimisticTRSANotEnoughShares(test *testing.T) {

	n := 10
	t := n/2 + 1

	testTRSANotEnoughShares(n,t, NewPessimisticTRSACryptoHandler(),test)
}

func TestPessimisticTRSASomeByzantineSignature(test *testing.T){
	testTRSASomeByzantineSignature(NewPessimisticTRSACryptoHandler(), test)
}

func TestPessimisticTRSAByzantineSignature(test *testing.T) {
	testTRSAByzantineSignature(NewPessimisticTRSACryptoHandler(), test)
}

