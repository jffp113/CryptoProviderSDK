package rsa

import (
	"errors"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

const BLS = "BLS256"

type blsHandler struct {
	scheme string
	suite pairing.Suite
}

func (self blsHandler) Sign(digest []byte, key crypto.PrivateKey) (signature []byte, err error) {
	priv,ok := key.(kyber.Scalar)

	if !ok {
		return nil,errors.New("invalid key")
	}
	return bls.Sign(self.suite, priv, digest)
}

func (self blsHandler) Verify(signature []byte, msg []byte, key crypto.PublicKey) error {
	pub,ok := key.(kyber.Point)

	if !ok {
		return errors.New("invalid key")
	}

	return bls.Verify(self.suite, pub, msg, signature)
}

func (self blsHandler) Aggregate(share [][]byte, digest []byte, key crypto.PublicKey, t, n int) (signature []byte, err error) {
	panic("Not implemented")
}

func (self blsHandler) Gen(n int, t int) (crypto.PublicKey, crypto.PrivateKeyList) {
	private, public := bls.NewKeyPair(self.suite, random.New())
	return public,
			crypto.PrivateKeyList{private}
}

func (self blsHandler) SchemeName() string {
	return self.scheme
}

func (self blsHandler) UnmarshalPublic(data []byte) crypto.PublicKey {
	pub := bn256.NewSuiteG2().G2().Point()
	err := pub.UnmarshalBinary(data)

	if err != nil {
		panic(err)
	}

	return  pub
}

func (self blsHandler) UnmarshalPrivate(data []byte) crypto.PrivateKey {
	privKey := bn256.NewSuiteG2().Scalar()
	err := privKey.UnmarshalBinary(data)//priv

	if err != nil {
		panic(err)
	}

	return  privKey
}

func NewBLSKeyGenerator256() crypto.KeyShareGenerator {
	return blsHandler{BLS,bn256.NewSuite()}
}

func NewBLS256() crypto.SignerVerifierAggregator {
	return blsHandler{BLS,bn256.NewSuite()}
}

func NewBLS256Handler() crypto.THSignerHandler{
	return blsHandler{BLS,bn256.NewSuite()}
}