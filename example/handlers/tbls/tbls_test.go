package tbls

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTBLS(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessSignature(n, i, test)
	}
}

func tblsSuccessSignature(n, t int, test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	keygen := NewTBLS256KeyGenerator()
	tbls := NewTBLS256()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares {

		s, err := tbls.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	sig, err := tbls.Aggregate(sigShares, msg, pub, t, n)

	require.Nil(test, err)

	err = tbls.Verify(sig, msg, pub)
	require.Nil(test, err)
}

func TestTBLSNotEnoughShares(test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	keygen := NewTBLS256KeyGenerator()
	tbls := NewTBLS256()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares[0 : t-1] {
		s, err := tbls.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = tbls.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}

func TestTBLSMarshallAndUnMarshall(test *testing.T) {
	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessMarshallAndUnmarshallSignature(n, i, test)
	}
}

func tblsSuccessMarshallAndUnmarshallSignature(n, t int, test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	keygen := NewTBLS256KeyGenerator()
	tbls := NewTBLS256()
	pub, shares := keygen.Gen(n, t)
	h := NewTBLS256CryptoHandler()
	sigShares := make([][]byte, 0)
	for _, x := range shares {
		b, err := x.MarshalBinary()
		require.Nil(test, err)
		x2 := h.UnmarshalPrivate(b)

		s, err := tbls.Sign(msg, x2)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	b, err := pub.MarshalBinary()
	require.Nil(test, err)
	pub2 := h.UnmarshalPublic(b)

	sig, err := tbls.Aggregate(sigShares, msg, pub2, t, n)

	require.Nil(test, err)

	err = tbls.Verify(sig, msg, pub2)
	require.Nil(test, err)
}

func TestTBLSByzantineSignature(test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	keygen := NewTBLS256KeyGenerator()
	tbls := NewTBLS256()
	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for i, x := range shares {
		var s []byte
		var err error
		if i == 2 {
			s, err = tbls.Sign([]byte("Byzantine"), x)
		} else {
			s, err = tbls.Sign(msg, x)
		}

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = tbls.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}
