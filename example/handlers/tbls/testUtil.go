package tbls

import (
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func tblsSuccessSignature(n, t int, handler crypto.THSignerHandler,test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	//keygen := NewTBLS256KeyGenerator()
	//tbls := NewTBLS256()
	pub, shares := handler.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares {

		s, err := handler.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	sig, err := handler.Aggregate(sigShares, msg, pub, t, n)

	require.Nil(test, err)

	err = handler.Verify(sig, msg, pub)
	require.Nil(test, err)
}

func notEnoughShares(handler crypto.THSignerHandler,test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	pub, shares := handler.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares[0 : t-1] {
		s, err := handler.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = handler.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}

func tblsByzantineSignature(handler crypto.THSignerHandler,test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	pub, shares := handler.Gen(n, t)

	sigShares := make([][]byte, 0)
	for i, x := range shares {
		var s []byte
		var err error
		if i % 2 == 0{
			s, err = handler.Sign([]byte("Byzantine"), x)
		} else {
			s, err = handler.Sign(msg, x)
		}

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = handler.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}

func tblsHalfByzantineSignature(handler crypto.THSignerHandler,test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	pub, shares := handler.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares {
		var s []byte
		var err error

		s, err = handler.Sign(msg, x)

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	destroyUpToShares(n - t, sigShares)

	_, err = handler.Aggregate(sigShares, msg, pub, t, n)

	require.Nil(test, err)
}

func destroyUpToShares(t int, shares [][]byte){
	var destroyed int

	for i,_ := range shares{
		p := rand.Float64()

		if p > 0.5 && destroyed < t {
			shares[i] = []byte("Destroyed")
			destroyed++
		}
	}
}

