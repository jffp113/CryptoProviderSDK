package main

import (
	"bytes"
	go_crypto "crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/niclabs/tcrsa"
)

var (
	keyError = errors.New("invalid key")
)

const HashType = go_crypto.SHA256

type trsa struct {

}

type signatureShare struct {
	*tcrsa.SigShare
}

func (sig signatureShare) MarshallBinary() (data []byte, err error) {
	return marshallToJSON(&sig)
}

type privKey struct {
	Meta *tcrsa.KeyMeta
	KeyShare *tcrsa.KeyShare
}

func (p privKey) MarshalBinary() (data []byte, err error) {
	return marshallToJSON(&p)
}

type pubKey struct {
	Meta *tcrsa.KeyMeta
}

func (p pubKey) MarshalBinary() (data []byte, err error) {
	return marshallToJSON(&p)
}

func (self trsa) Sign(digest []byte, key crypto.PrivateKey) (signature []byte, err error) {
	priv, ok := key.(privKey)

	if !ok {
		return nil, keyError
	}

	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(priv.Meta.PublicKey.Size(), HashType, docHash[:])

	if err != nil {
		return nil,err
	}

	sigShare , err := priv.KeyShare.Sign(docPKCS1, HashType, priv.Meta)

	if err != nil {
		return nil,err
	}

	return signatureShare{sigShare}.MarshallBinary()
}

func (self trsa) Verify(signature []byte, msg []byte, key crypto.PublicKey) error {
	pub, ok := key.(pubKey)

	if !ok {
		return keyError
	}

	docHash := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub.Meta.PublicKey, HashType, docHash[:], signature)
}

func (self trsa) Aggregate(share [][]byte, digest []byte, key crypto.PublicKey, t, n int) (signature []byte, err error) {
	pub, ok := key.(pubKey)

	if !ok {
		return nil,keyError
	}

	s := make(tcrsa.SigShareList,0)

	for _,v := range share {
		unmarshalled := signatureShare{}
		unmarshallFromJson(v,&unmarshalled)
		s = append(s,unmarshalled.SigShare)
	}

	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])
	return s.Join(docPKCS1, pub.Meta)
}

func (self trsa) Gen(n int, t int) (crypto.PublicKey, crypto.PrivateKeyList) {
	// Generate keys provides to u with a list of keyShares and the key metainformation.
	keyShares, keyMeta, err := tcrsa.NewKey(1024, uint16(t), uint16(n), nil)

	if err != nil{
		panic(err)
	}

	sl := make(crypto.PrivateKeyList,0)
	for _,v := range keyShares {
		sl = append(sl,privKey{
			Meta:     keyMeta,
			KeyShare: v,
		})
	}

	pubKey := pubKey{keyMeta}

	return pubKey, sl
}

func (self trsa) SchemeName() string {
	return "TRSA"
}

func (self trsa) UnmarshalPublic(data []byte) crypto.PublicKey {
	pub := pubKey{}
	unmarshallFromJson(data,&pub)
	return pub
}

func (self trsa) UnmarshalPrivate(data []byte) crypto.PrivateKey {
	priv := privKey{}
	unmarshallFromJson(data,&priv)
	return priv
}

func NewTRSAKeyGenerator() crypto.KeyShareGenerator {
	return &trsa{}
}

func NewTRSA() crypto.SignerVerifierAggregator {
	return &trsa{}
}

func NewTRSACryptoHandler() crypto.THSignerHandler {
	return &trsa{}
}

func marshallToJSON(v interface{}) ([]byte, error){
	var buffer bytes.Buffer        // Stand-in for a network connection
	enc := json.NewEncoder(&buffer) // Will write to network.
	err := enc.Encode(v)
	return buffer.Bytes(),err
}

func unmarshallFromJson(data []byte,v interface{}) {
	reader := bytes.NewReader(data)
	dec := json.NewDecoder(reader)
	dec.Decode(v)
}

func main() {
}


