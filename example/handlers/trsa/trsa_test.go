package trsa

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTRSA(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessSignature(n, i, test)
	}
}

func trsaSuccessSignature(n, t int, test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	keygen := NewTRSAKeyGenerator()
	trsa := NewTRSA()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares {

		s, err := trsa.Sign(msg, x)

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	sig, err := trsa.Aggregate(sigShares, msg, pub, t, n)
	require.Nil(test, err)

	err = trsa.Verify(sig, msg, pub)
	require.Nil(test, err)
}

func TestTRSANotEnoughShares(test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	n := 10
	t := n/2 + 1

	keygen := NewTRSAKeyGenerator()
	trsa := NewTRSA()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares[0 : t-1] {
		s, err := trsa.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = trsa.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}

func TestTRSAMarshallAndUnMarshall(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		trsaSuccessMarshallAndUnmarshallSignature(n, i, test)
	}
}

func trsaSuccessMarshallAndUnmarshallSignature(n, t int, test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	keygen := NewTRSAKeyGenerator()
	trsa := NewTRSA()
	pub, shares := keygen.Gen(n, t)
	h := NewTRSACryptoHandler()
	sigShares := make([][]byte, 0)
	for _, x := range shares {
		b, err := x.MarshalBinary()
		require.Nil(test, err)
		x2 := h.UnmarshalPrivate(b)

		s, err := trsa.Sign(msg, x2)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	b, err := pub.MarshalBinary()
	require.Nil(test, err)
	pub2 := h.UnmarshalPublic(b)

	sig, err := trsa.Aggregate(sigShares, msg, pub2, t, n)

	require.Nil(test, err)

	err = trsa.Verify(sig, msg, pub2)
	require.Nil(test, err)
}

func TestTRSAByzantineSignature(test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	n := 10
	t := n/2 + 1

	keygen := NewTRSAKeyGenerator()
	trsa := NewTRSA()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for i, x := range shares {
		var s []byte
		var err error
		if i == 1 {
			fmt.Println("Byzantine")
			s, err = trsa.Sign([]byte("Byzantine"), x)
		} else {
			s, err = trsa.Sign(msg, x)
		}

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	sig, err := trsa.Aggregate(sigShares, msg, pub, t, n)

	require.Nil(test, err) //TODO It should detect a error here NotNil

	err = trsa.Verify(sig, msg, pub)
	require.NotNil(test, err) //TODO However it is detected later
}
