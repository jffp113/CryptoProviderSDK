package tbls

import (
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	ths "go.dedis.ch/kyber/v3/sign/tbls"
)

const TBLSPessimistic = "TBLS256Pessimistic"


func recoverPessimistic(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error){
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := ths.SigShare(sig)
		i, err := s.Index()
		if err != nil {
			continue
		}
		if err = bls.Verify(suite, public.Eval(i).V, msg, s.Value()); err != nil {
			continue
		}
		point := suite.G1().Point()
		if err := point.UnmarshalBinary(s.Value()); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	commit, err := share.RecoverCommit(suite.G1(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
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



