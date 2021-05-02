package tbls

import (
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	ths "go.dedis.ch/kyber/v3/sign/tbls"
)

func NewTBLS256() crypto.SignerVerifierAggregator {
	return &tbls{
		bn256.NewSuite(),
			ths.Recover,
	}
}


func NewTBLS256CryptoHandler() crypto.THSignerHandler {
	return tblsHandler{
		NewTBLS256(),
		NewTBLS256KeyGenerator(),
		"TBLS256"}
}
