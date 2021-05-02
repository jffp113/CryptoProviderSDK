package main

import (
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/rsa"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/trsa"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	T = 3
	N = 5
)
var Digest = []byte("Hello")


var resultSig []byte
var resultPublicKey crypto.PublicKey
var resultPrivateKey crypto.PrivateKeyList


//Init key materials to speed the test
//TBLS Material
var tbls256Priv crypto.PrivateKeyList
var tbls256Pub crypto.PublicKey


//TRSA Material
var trsa1024Priv crypto.PrivateKeyList
var trsa1024Pub crypto.PublicKey

var trsa2048Priv crypto.PrivateKeyList
var trsa2048Pub crypto.PublicKey

var trsa3072Priv crypto.PrivateKeyList
var trsa3072Pub crypto.PublicKey

//RSA material
var rsa1024Priv crypto.PrivateKeyList
var rsa1024Pub crypto.PublicKey

var rsa2048Priv crypto.PrivateKeyList
var rsa2048Pub crypto.PublicKey

var rsa3072Priv crypto.PrivateKeyList
var rsa3072Pub crypto.PublicKey

func init() {
	tbls256Pub,tbls256Priv = tbls.NewTBLS256KeyGenerator().Gen(N,T)

	trsa1024Pub,trsa1024Priv = trsa.NewTRSAKeyGenerator(1024).Gen(N,T)
	trsa2048Pub,trsa2048Priv = trsa.NewTRSAKeyGenerator(2048).Gen(N,T)
	trsa3072Pub,trsa3072Priv = trsa.NewTRSAKeyGenerator(3072).Gen(N,T)

	rsa1024Pub,rsa1024Priv = rsa.NewRSAKeyGenerator(1024).Gen(N,T)
	rsa2048Pub,rsa2048Priv = rsa.NewRSAKeyGenerator(2048).Gen(N,T)
	rsa3072Pub,rsa3072Priv = rsa.NewRSAKeyGenerator(3072).Gen(N,T)

}

/****************
 *Local Tests start here
 ****************/

/****************
 * TBLS Benchmark
 ****************/
func BenchmarkTBLS256LocalGen(b *testing.B) {
	keygen := tbls.NewTBLS256KeyGenerator()
	benchmarkGen(b,keygen)
}

func BenchmarkTBLS256LocalSign(b *testing.B) {
	//keygen := tbls.NewTBLS256KeyGenerator()
	tbls := tbls.NewTBLS256Optimistic()
	benchmarkSign(b,tbls,tbls256Priv)
}

func BenchmarkTBLS256LocalAggregate(b *testing.B) {
	//keygen := tbls.NewTBLS256KeyGenerator()
	tbls := tbls.NewTBLS256Optimistic()
	benchmarkAggregate(b,tbls,tbls256Pub,tbls256Priv)
}

func BenchmarkTBLS256LocalVerify(b *testing.B) {
	//keygen := tbls.NewTBLS256KeyGenerator()
	tbls := tbls.NewTBLS256Optimistic()
	benchmarkVerify(b,tbls,tbls256Pub,tbls256Priv)
}


/****************
 * BLS Benchmark
 ****************/



/****************
 * TRSA Benchmark
 ****************/

//1024 STARTS HERE

func BenchmarkTRSA1024LocalGen(b *testing.B) {
	keygen := trsa.NewTRSAKeyGenerator(1024)
	benchmarkGen(b,keygen)
}

func BenchmarkTRSA1024LocalSign(b *testing.B) {
	//keygen := trsa.NewTRSAKeyGenerator(1024)
	trsa := trsa.NewOptimisticTRSA(1024)
	benchmarkSign(b,trsa,trsa1024Priv)
}

func BenchmarkTRSA1024LocalAggregate(b *testing.B) {
	//keygen := trsa.NewTRSAKeyGenerator(1024)
	trsa := trsa.NewOptimisticTRSA(1024)
	benchmarkAggregate(b,trsa,trsa1024Pub,trsa1024Priv)
}

func BenchmarkTRSA1024LocalVerify(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(1024)
	benchmarkVerify(b,trsa,trsa1024Pub,trsa1024Priv)
}

//2048 STARTS HERE

func BenchmarkTRSA2048LocalGen(b *testing.B) {
	keygen := trsa.NewTRSAKeyGenerator(2048)
	benchmarkGen(b,keygen)
}

func BenchmarkTRSA2048LocalSign(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(2048)
	benchmarkSign(b,trsa,trsa2048Priv)
}

func BenchmarkTRSA2048LocalAggregate(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(2048)
	benchmarkAggregate(b,trsa,trsa2048Pub,trsa2048Priv)
}

func BenchmarkTRSA2048LocalVerify(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(2048)
	benchmarkVerify(b,trsa,trsa2048Pub,trsa2048Priv)
}

//3072 STARTS HERE
func BenchmarkTRSA3072LocalGen(b *testing.B) {
	keygen := trsa.NewTRSAKeyGenerator(3072)
	benchmarkGen(b,keygen)
}

func BenchmarkTRSA3072LocalSign(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(3072)
	benchmarkSign(b,trsa,trsa3072Priv)
}

func BenchmarkTRSA3072LocalAggregate(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(3072)
	benchmarkAggregate(b,trsa,trsa3072Pub,trsa3072Priv)
}

func BenchmarkTRSA3072LocalVerify(b *testing.B) {
	trsa := trsa.NewOptimisticTRSA(3072)
	benchmarkVerify(b,trsa,trsa3072Pub,trsa3072Priv)
}


/****************
 * RSA Benchmark
 ****************/

//1024
func BenchmarkRSA1024LocalGen(b *testing.B) {
	keygen := rsa.NewRSAKeyGenerator(1024)
	benchmarkGen(b,keygen)
}

func BenchmarkRSA1024LocalSign(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(1024)

	benchmarkSign(b,trsa,rsa1024Priv)
}

func BenchmarkRSA1024LocalVerify(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(1024)
	benchmarkVerifyNonThreshold(b,trsa,rsa1024Pub,rsa1024Priv)
}


//2048
func BenchmarkRSA2048LocalGen(b *testing.B) {
	keygen := rsa.NewRSAKeyGenerator(2048)
	benchmarkGen(b,keygen)
}

func BenchmarkRSA2048LocalSign(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(2048)

	benchmarkSign(b,trsa,rsa2048Priv)
}

func BenchmarkRSA2048LocalVerify(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(2048)
	benchmarkVerifyNonThreshold(b,trsa,rsa2048Pub,rsa2048Priv)
}

//3072
func BenchmarkRSA3072LocalGen(b *testing.B) {
	keygen := rsa.NewRSAKeyGenerator(3072)
	benchmarkGen(b,keygen)
}

func BenchmarkRSA3072LocalSign(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(3072)

	benchmarkSign(b,trsa,rsa3072Priv)
}

func BenchmarkRSA3072LocalVerify(b *testing.B) {
	//keygen := rsa.NewRSAKeyGenerator(1024)
	trsa := rsa.NewRSA(3072)
	benchmarkVerifyNonThreshold(b,trsa,rsa3072Pub,rsa3072Priv)
}

/****************
 * Benchmark Utils
 ****************/

func benchmarkGen(b *testing.B,keygen crypto.KeyShareGenerator){
	b.ResetTimer()
	var pub crypto.PublicKey
	var privList crypto.PrivateKeyList
	for i := 0; i < b.N; i++ {
		pub,privList = keygen.Gen(N,T)
	}
	resultPublicKey = pub
	resultPrivateKey = privList
}

func benchmarkSign(b *testing.B,sva crypto.SignerVerifierAggregator, privList crypto.PrivateKeyList){

	//_,privList := keygen.Gen(N,T)

	b.ResetTimer()
	var sig []byte
	for i := 0; i < b.N; i++ {
		sig, _ = sva.Sign(Digest,privList[0])
	}
	resultSig = sig
}

func benchmarkVerifyNonThreshold(b *testing.B,sva crypto.SignerVerifierAggregator ,pub crypto.PublicKey, privList crypto.PrivateKeyList){
	//pub,privList := keygen.Gen(N,T)
	sig,err := sva.Sign(Digest,privList[0])
	assert.Nil(b,err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := sva.Verify(sig,Digest,pub)
		assert.Nil(b,err)
	}
}

func benchmarkVerify(b *testing.B,sva crypto.SignerVerifierAggregator ,pub crypto.PublicKey, privList crypto.PrivateKeyList){
	var sigShares [][]byte

	for i := 0 ; i < N ;i++ {
		sig,err := sva.Sign(Digest,privList[i])
		assert.Nil(b,err)
		sigShares = append(sigShares,sig)
	}

	sig,err := sva.Aggregate(sigShares,Digest,pub,T,N)
	assert.Nil(b,err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := sva.Verify(sig,Digest,pub)
		assert.Nil(b,err)
	}
}

func benchmarkAggregate(b *testing.B,sva crypto.SignerVerifierAggregator, pub crypto.PublicKey, privList crypto.PrivateKeyList){
	var sigShares [][]byte

	for i := 0 ; i < N ;i++ {
		sig,err := sva.Sign(Digest,privList[i])
		assert.Nil(b,err)
		sigShares = append(sigShares,sig)
	}

	var sig []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig,err = sva.Aggregate(sigShares,Digest,pub,T,N)
		assert.Nil(b,err)
	}

	resultSig = sig
}

