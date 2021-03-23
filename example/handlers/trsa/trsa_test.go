package trsa

import (
	"testing"
)

func TestTRSA(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessSignature(n, i, NewTRSACryptoHandler(),test)
	}
}

func TestTRSANotEnoughShares(test *testing.T) {

	n := 10
	t := n/2 + 1

	testTRSANotEnoughShares(n,t, NewTRSACryptoHandler(),test)
}

func TestTRSAMarshallAndUnMarshall(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessMarshallAndUnmarshallSignature(n, i,NewTRSACryptoHandler(), test)
	}
}

func TestTRSAByzantineSignature(test *testing.T) {

	testTRSAByzantineSignature(NewTRSACryptoHandler(), test)
}
