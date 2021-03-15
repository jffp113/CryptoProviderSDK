package main

import (
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/client"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

const URI = "tcp://127.0.0.1:9000"
const SCHEME = "TBLS256"

var context, err = client.NewCryptoFactory(URI)

func TestTBLSClientServer(test *testing.T) {
	_ = log.SetLogLevel("crypto_client", "debug")
	_ = log.SetLogLevel("signer_processor", "debug")

	require.Nil(test, err)

	gen, close := context.GetKeyGenerator(SCHEME)
	defer close.Close()
	sign, close := context.GetSignerVerifierAggregator(SCHEME)
	defer close.Close()

	time.Sleep(1 * time.Second)
	go setupDistributesCrypto()
	time.Sleep(1 * time.Second)

	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessSignature(n, t, gen, sign, test)
	}

}

func setupDistributesCrypto() {
	processor := crypto.NewSignerProcessor(URI)
	processor.AddHandler(tbls.NewTBLS256CryptoHandler())
	processor.Start()
}

func tblsSuccessSignature(n, t int, keygen crypto.KeyShareGenerator, tbls crypto.SignerVerifierAggregator, test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

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

func TestTBLSNotEnoughSharesServerError(test *testing.T) {
	//_ = log.SetLogLevel("crypto_client", "debug")
	//context , err := client.NewCryptoFactory(URI)

	require.Nil(test, err)

	keygen, keygenClose := context.GetKeyGenerator(SCHEME)
	defer keygenClose.Close()
	tbls, tblsClose := context.GetSignerVerifierAggregator(SCHEME)
	defer tblsClose.Close()

	time.Sleep(1 * time.Second)
	go setupDistributesCrypto()
	time.Sleep(1 * time.Second)

	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

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

func TestStress(test *testing.T) {
	goroutines := 40
	_ = log.SetLogLevel("crypto_client", "debug")
	_ = log.SetLogLevel("signer_processor", "debug")

	keygen, close := context.GetKeyGenerator(SCHEME)
	defer close.Close()

	time.Sleep(1 * time.Second)
	go setupDistributesCrypto()
	time.Sleep(1 * time.Second)

	msg := []byte("Test TBLS")

	n := 10
	t := n/2 + 1

	_, shares := keygen.Gen(n, t)

	//sigShares := make([][]byte, 0)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			tbls, close := context.GetSignerVerifierAggregator(SCHEME)
			defer close.Close()
			for i := 0; i < 200; i++ {
				_, err := tbls.Sign(msg, shares[0])
				require.Nil(test, err)
			}
			wg.Done()
		}()
	}

	wg.Wait()

}
