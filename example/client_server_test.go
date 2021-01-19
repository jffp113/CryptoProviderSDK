package main

import (
	"github.com/jffp113/CryptoProviderSDK/client"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const URI =  "tcp://127.0.0.1:9000"
const SCHEME = "TBLS256"


var context , err = client.NewCryptoFactory(URI)

func TestTBLSClientServer(test *testing.T) {
	//_ = log.SetLogLevel("crypto_client", "debug")

	require.Nil(test, err)

	gen := context.GetKeyGenerator(SCHEME)
	sign := context.GetSignerVerifierAggregator(SCHEME)

	time.Sleep(1*time.Second)
	go setupDistributesCrypto()
	time.Sleep(1*time.Second)

	n := 10
	t := n/2 + 1

	for i := t; i <= n; i++ {
		tblsSuccessSignature(n, t,gen,sign,test)
	}


}

func setupDistributesCrypto(){
	processor := crypto.NewSignerProcessor(URI)
	processor.AddHandler(tbls.NewTBLS256CryptoHandler())
	processor.Start()
}

func tblsSuccessSignature(n, t int,keygen crypto.KeyShareGenerator, tbls crypto.SignerVerifierAggregator, test *testing.T) {
	var err error
	msg := []byte("Test TBLS")

	pub, shares := keygen.Gen(n, t)

	sigShares := make([][]byte, 0)
	for _, x := range shares {

		s, err := tbls.Sign(msg, x)
		require.Nil(test, err)
		sigShares = append(sigShares, s)
	}

	sig, err := tbls.Aggregate(sigShares, msg, pub,t,n)

	require.Nil(test, err)

	err = tbls.Verify(sig, msg, pub)
	require.Nil(test, err)
}

func TestTBLSNotEnoughSharesServerError(test *testing.T) {
	//_ = log.SetLogLevel("crypto_client", "debug")
	//context , err := client.NewCryptoFactory(URI)

	require.Nil(test, err)

	keygen := context.GetKeyGenerator(SCHEME)
	tbls := context.GetSignerVerifierAggregator(SCHEME)

	time.Sleep(1*time.Second)
	go setupDistributesCrypto()
	time.Sleep(1*time.Second)

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

	_, err = tbls.Aggregate(sigShares, msg, pub,t,n)

	require.NotNil(test, err)

}

