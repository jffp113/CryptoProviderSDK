package tbls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	ths "go.dedis.ch/kyber/v3/sign/tbls"
	"io"
)

var (
	privateKeyError = errors.New("invalid private key")
)

type privKey struct {
	priv *share.PriShare
}

type pubKey struct {
	pub *share.PubPoly
}
func (priv privKey) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	suite := bn256.NewSuite()

	err = suite.Write(&buffer, priv.priv)

	return buffer.Bytes(), err
}

func (pub pubKey) MarshalBinary() (data []byte, err error) {
	var buffer bytes.Buffer

	_, commits := pub.pub.Info()

	binary.Write(&buffer, binary.LittleEndian, int64(len(commits)))

	for _, c := range commits {
		data, _ := c.MarshalBinary()
		buffer.Write(data)
	}

	return buffer.Bytes(), err
}

type AggregateTBLS func(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error)
type tbls struct {
	suite pairing.Suite
	recover AggregateTBLS
}



func (t *tbls) Sign(digest []byte, key crypto.PrivateKey) ([]byte, error) {
	priv, ok := key.(privKey)

	if !ok {
		return nil, privateKeyError
	}

	return ths.Sign(t.suite, priv.priv, digest)
}

func (t *tbls) Verify(signature, msg []byte, key crypto.PublicKey) error {
	pub, ok := key.(pubKey)

	if !ok {
		return errors.New(fmt.Sprintf("Error Unmarshalling public key: %v",privateKeyError))
	}

	return bls.Verify(t.suite, pub.pub.Commit(), msg, signature)
}

func (tbls *tbls) Aggregate(shares [][]byte, digest []byte, key crypto.PublicKey, t, n int) ([]byte, error) {
	pub, ok := key.(pubKey)

	if !ok {
		return nil, privateKeyError
	}

	//return ths.Recover(tbls.suite, pub.pub, digest, shares, t, n)
	return tbls.recover(tbls.suite, pub.pub, digest, shares, t, n)
}

type tblsKeyGenerator struct {
	suite pairing.Suite
}

func (g *tblsKeyGenerator) Gen(n int, t int) (crypto.PublicKey, crypto.PrivateKeyList) {
	suite := g.suite
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())

	shares := make([]crypto.PrivateKey, n)
	for i, v := range priPoly.Shares(n) {
		shares[i] = privKey{v}
	}

	return pubKey{pubPoly}, shares
}

func NewTBLS256KeyGenerator() crypto.KeyShareGenerator {
	return &tblsKeyGenerator{
		bn256.NewSuite(),
	}
}

type tblsHandler struct {
	crypto.SignerVerifierAggregator
	crypto.KeyShareGenerator
	schemeName string
}

func (tbls tblsHandler) SchemeName() string {
	return tbls.schemeName
}

func (tbls tblsHandler) UnmarshalPublic(data []byte) crypto.PublicKey {
	suite := bn256.NewSuiteG2()
	reader := bytes.NewReader(data)

	var nCommits int64
	binary.Read(reader, binary.LittleEndian, &nCommits)

	sl := make([]kyber.Point, nCommits)

	for i, _ := range sl {
		bytes := make([]byte, 128)
		io.ReadFull(reader, bytes)
		p := suite.Point()
		p.UnmarshalBinary(bytes)

		sl[i] = p
	}

	return pubKey{share.NewPubPoly(suite.G2(), suite.G2().Point().Base(), sl)}
}

func (tbls tblsHandler) UnmarshalPrivate(data []byte) crypto.PrivateKey {
	suite := bn256.NewSuiteG1()
	reader := bytes.NewReader(data)
	privShare := share.PriShare{}

	_ = suite.Read(reader, &privShare)

	return privKey{&privShare}
}