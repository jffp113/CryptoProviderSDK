package trsa

import (
	"crypto/sha256"
	"errors"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/go-util/algorithms/twiddle"
	"github.com/niclabs/tcrsa"
)

const PessimisticScheme = "TRSA/Pessimistic"

func aggregatePessimistic(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error){
	if len(sigShares) < t {
		return nil, errors.New("not enough signatures")
	}

	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])

	tw := twiddle.New(t, len(sigShares))

	for b := tw.Next(); b != nil; b = tw.Next() {
		var perm []*tcrsa.SigShare

		for i, c := range b {
			if c {
				perm = append(perm, sigShares[i])
			}
		}

		valid := getValidShares(perm,docPKCS1,pub)

		if len(valid) >= t {
			return valid.Join(docPKCS1, pub.Meta)
		}

	}
	return nil, errors.New("no valid combination found")
}


func NewPessimisticTRSA() crypto.SignerVerifierAggregator {
	return &trsa{
		scheme: PessimisticScheme,
		aggregate: aggregatePessimistic,
	}
}

func NewPessimisticTRSACryptoHandler() crypto.THSignerHandler {
	return &trsa{
		scheme: PessimisticScheme,
		aggregate: aggregatePessimistic,
	}
}

