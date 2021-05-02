package trsa

import (
	"crypto/sha256"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/niclabs/tcrsa"
)

const OptimisticScheme = "TRSA%vOptimistic"

func aggregateOptimistic(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error){
	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])

	if err != nil {
		return
	}
	valid := getValidShares(sigShares,docPKCS1,pub)
	return valid.Join(docPKCS1, pub.Meta)
}

func NewOptimisticTRSA(size int) crypto.SignerVerifierAggregator {
	return &trsa{
		scheme: fmt.Sprintf(OptimisticScheme,size),
		aggregate: aggregateOptimistic,
		keySize: size,
	}
}

func NewOptimisticTRSACryptoHandler(size int) crypto.THSignerHandler {
	return &trsa{
		scheme: fmt.Sprintf(OptimisticScheme,size),
		aggregate: aggregateOptimistic,
		keySize: size,
	}
}
