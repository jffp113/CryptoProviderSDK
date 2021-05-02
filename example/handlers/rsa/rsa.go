package rsa

import (
	"crypto/rand"
	gocrypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
)

const RSA = "RSA"

type rsaHandler struct {
	scheme string
	keySize int
}

type rsaPubKey struct {
	*rsa.PublicKey
}

func (r rsaPubKey) MarshalBinary() (data []byte, err error) {
	return x509.MarshalPKCS1PublicKey(r.PublicKey),nil
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

func (r rsaPrivateKey) MarshalBinary() (data []byte, err error) {
	return x509.MarshalPKCS1PrivateKey(r.PrivateKey),nil
}


func (self rsaHandler) Sign(digest []byte, key crypto.PrivateKey) (signature []byte, err error) {
	v,ok := key.(rsaPrivateKey)

	if !ok {
		return nil,errors.New("invalid key")
	}

	rng := rand.Reader
	hashed := sha256.Sum256(digest)
	return rsa.SignPKCS1v15(rng,v.PrivateKey,gocrypto.SHA256,hashed[:])
}

func (self rsaHandler) Verify(signature []byte, msg []byte, key crypto.PublicKey) error {
	v,ok := key.(rsaPubKey)

	if !ok {
		return errors.New("invalid key")
	}

	hashed := sha256.Sum256(msg)

	return rsa.VerifyPKCS1v15(v.PublicKey,gocrypto.SHA256,hashed[:],signature)
}

func (self rsaHandler) Aggregate(share [][]byte, digest []byte, key crypto.PublicKey, t, n int) (signature []byte, err error) {
	panic("Not implemented")
}

func (self rsaHandler) Gen(n int, t int) (crypto.PublicKey, crypto.PrivateKeyList) {
	priv, _ := rsa.GenerateKey(rand.Reader, self.keySize)

	return rsaPubKey{&priv.PublicKey},
			crypto.PrivateKeyList{rsaPrivateKey{priv}}
}

func (self rsaHandler) SchemeName() string {
	return self.scheme
}

func (self rsaHandler) UnmarshalPublic(data []byte) crypto.PublicKey {
	pubKey,_ := x509.ParsePKCS1PublicKey(data)
	return  rsaPubKey{pubKey}
}

func (self rsaHandler) UnmarshalPrivate(data []byte) crypto.PrivateKey {
	privKey,_ := x509.ParsePKCS1PrivateKey(data)
	return  rsaPrivateKey{privKey}
}

func NewRSAKeyGenerator(keySize int) crypto.KeyShareGenerator {
	return &rsaHandler{RSA + fmt.Sprint(keySize),keySize}
}

func NewRSA(keySize int) crypto.SignerVerifierAggregator {
	return &rsaHandler{RSA + fmt.Sprint(keySize),keySize}
}
