package trsa

import (
	"crypto/sha256"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/niclabs/tcrsa"
)

const NormalScheme = "TRSA%v"

func aggregateNormal(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error) {
	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])

	valid := getValidShares(sigShares,docPKCS1,pub)
	return valid.Join(docPKCS1, pub.Meta)
}

func NewTRSA(size int) crypto.SignerVerifierAggregator {
	return &trsa{
		scheme: fmt.Sprintf(NormalScheme,size),
		aggregate: aggregateNormal,
		keySize: size,
	}
}

func NewTRSACryptoHandler(size int) crypto.THSignerHandler {
	return &trsa{
		scheme: fmt.Sprintf(NormalScheme,size),
		aggregate: aggregateNormal,
		keySize: size,
	}
}

