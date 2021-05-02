package trsa

import (
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/stretchr/testify/require"
	"math/rand"
	"sync"
	"testing"
)

var publicKeyTest map[string]crypto.PublicKey
var privateSharesTest map[string]crypto.PrivateKeyList
var once = &sync.Once{}

func initTests() {
	/* load test data */
	keygen := NewTRSAKeyGenerator(1024)
	n := 10
	t := n/2 + 1

	publicKeyTest = make(map[string]crypto.PublicKey)
	privateSharesTest = make(map[string]crypto.PrivateKeyList)

	for i := t; i <= n; i++ {
		pub, shares := keygen.Gen(n, i)
		publicKeyTest[getEntryName(i,n)] = pub
		privateSharesTest[getEntryName(i,n)] = shares
	}
}


func getEntryName(t,n int) string{
	return fmt.Sprintf("%v/%v",t,n)
}


func trsaSuccessSignature(n, t int, trsa crypto.THSignerHandler,test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	once.Do(initTests)

	sigShares := make([][]byte, 0)
	pub := publicKeyTest[getEntryName(t,n)]
	shares := privateSharesTest[getEntryName(t,n)]

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


func testTRSANotEnoughShares(n, t int, trsa crypto.THSignerHandler,test *testing.T){
	var err error
	msg := []byte("Test TRSA")

	once.Do(initTests)

	pub := publicKeyTest[getEntryName(t,n)]
	shares := privateSharesTest[getEntryName(t,n)]

	sigShares := make([][]byte, 0)
	for _, x := range shares[0 : t-1] {
		s, err := trsa.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = trsa.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err)
}

func trsaSuccessMarshallAndUnmarshallSignature(n, t int,trsa crypto.THSignerHandler, test *testing.T) {
	var err error
	msg := []byte("Test TRSA")

	once.Do(initTests)


	pub := publicKeyTest[getEntryName(t,n)]
	shares := privateSharesTest[getEntryName(t,n)]
	//h := NewTRSACryptoHandler(1024)
	sigShares := make([][]byte, 0)
	for _, x := range shares {
		b, err := x.MarshalBinary()
		require.Nil(test, err)
		x2 := trsa.UnmarshalPrivate(b)

		s, err := trsa.Sign(msg, x2)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	b, err := pub.MarshalBinary()
	require.Nil(test, err)
	pub2 := trsa.UnmarshalPublic(b)

	sig, err := trsa.Aggregate(sigShares, msg, pub2, t, n)

	require.Nil(test, err)

	err = trsa.Verify(sig, msg, pub2)
	require.Nil(test, err)
}

func testTRSAByzantineSignature(trsa crypto.THSignerHandler, test *testing.T) {
	var err error
	msg := []byte("Test TRSA")


	n := 10
	t := n/2 + 1

	once.Do(initTests)

	pub := publicKeyTest[getEntryName(t,n)]
	shares := privateSharesTest[getEntryName(t,n)]
	sigShares := make([][]byte, 0)
	for i, x := range shares {
		var s []byte
		var err error
		if i % 2 == 0 {
			s, err = trsa.Sign([]byte("Byzantine"), x)
		} else {
			s, err = trsa.Sign(msg, x)
		}

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	_, err = trsa.Aggregate(sigShares, msg, pub, t, n)

	require.NotNil(test, err) //TODO It should detect a error here NotNil

}

func testTRSASomeByzantineSignature(trsa crypto.THSignerHandler, test *testing.T) {
	var err error
	msg := []byte("Test TRSA")


	n := 10
	t := n/2 + 1

	once.Do(initTests)

	pub := publicKeyTest[getEntryName(t,n)]
	shares := privateSharesTest[getEntryName(t,n)]
	sigShares := make([][]byte, 0)
	for _, x := range shares {

		s, err := trsa.Sign(msg, x)

		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	destroyUpToShares(t - 1, sigShares)
	sig, err := trsa.Aggregate(sigShares, msg, pub, t, n)

	require.Nil(test, err)

	err = trsa.Verify(sig, msg, pub)
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
