package trsa

import (
	"crypto/sha256"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/niclabs/tcrsa"
)

const NormalScheme = "TRSA"

func aggregateNormal(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error) {
	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])

	valid := getValidShares(sigShares,docPKCS1,pub)
	return valid.Join(docPKCS1, pub.Meta)
}


func NewTRSA() crypto.SignerVerifierAggregator {
	return &trsa{
		scheme: NormalScheme,
		aggregate: aggregateNormal,
	}
}

func NewTRSACryptoHandler() crypto.THSignerHandler {
	return &trsa{
		scheme: NormalScheme,
		aggregate: aggregateNormal,
	}
}

