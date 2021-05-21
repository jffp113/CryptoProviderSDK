package trsa

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/niclabs/tcrsa"
)

const PessimisticScheme = "TRSA%vPessimistic"

func aggregatePessimistic(sigShares tcrsa.SigShareList,digest []byte,pub pubKey, t, n int) (signature []byte, err error){
	docHash := sha256.Sum256(digest)
	docPKCS1, err := tcrsa.PrepareDocumentHash(pub.Meta.PublicKey.Size(), HashType, docHash[:])

	if err != nil {
		return
	}
	valid := getValidShares(sigShares,docPKCS1,pub)


	sig,err := valid.Join(docPKCS1, pub.Meta)

	if err != nil {
		return []byte{},err
	}

	err = rsa.VerifyPKCS1v15(pub.Meta.PublicKey, HashType, docHash[:], sig)

	return sig,err
}

func NewPessimisticTRSA(size int) crypto.SignerVerifierAggregator {
	return &trsa{
		scheme: fmt.Sprintf(PessimisticScheme,size),
		aggregate: aggregatePessimistic,
		keySize: size,
	}
}

func NewPessimisticTRSACryptoHandler(size int) crypto.THSignerHandler {
	return &trsa{
		scheme: fmt.Sprintf(PessimisticScheme,size),
		aggregate: aggregatePessimistic,
		keySize: size,
	}
}

