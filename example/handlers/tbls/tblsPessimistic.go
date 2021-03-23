package tbls

import (
	"errors"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/go-util/algorithms/twiddle"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	ths "go.dedis.ch/kyber/v3/sign/tbls"
)

const TBLSPessimistic = "TBLS256/Pessimistic"

func recoverPessimistic(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error){
	if len(sigs) < t {
		return nil, errors.New("not enough signatures")
	}

	tw := twiddle.New(t, len(sigs))

	for b := tw.Next(); b != nil; b = tw.Next() {
		var perm [][]byte

		for i,c := range b {
			if c {
				perm = append(perm,sigs[i])
			}
		}
		//fmt.Println(perm)
		sig,err := ths.Recover(suite,public,msg,perm,t,n)
		if err == nil {
			return sig,nil
		}
	}
	return nil, errors.New("no valid combination found")
}

func NewTBLS256Pessimistic() crypto.SignerVerifierAggregator {
	return &tbls{
			bn256.NewSuite(),
		recoverPessimistic,
		}
}

func NewTBLS256PessimisticCryptoHandler() crypto.THSignerHandler {
	return tblsHandler{
		NewTBLS256Pessimistic(),
		NewTBLS256KeyGenerator(),
		TBLSPessimistic}
}



