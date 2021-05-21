package trsa

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/go-util/algorithms/twiddle"
	"github.com/niclabs/tcrsa"
)

const OptimisticScheme = "TRSA%vOptimistic"



func aggregateOptimistic(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error){
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

		 sig,err := tcrsa.SigShareList(perm).Join(docPKCS1, pub.Meta)
		 if err != nil {
		 	continue
		 }

		err = rsa.VerifyPKCS1v15(pub.Meta.PublicKey, HashType, docHash[:], sig)

		if err == nil {
			return sig,nil
		}

	}
	return nil, errors.New("no valid combination found")
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
