package tbls

import (
	"errors"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/go-util/algorithms/twiddle"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	ths "go.dedis.ch/kyber/v3/sign/tbls"
)

const TBLSOptimistic = "TBLS256Optimistic"

func recoverOptimistic(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error){
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
		sig,err := recover(suite,public,msg,perm,t,n)
		if err != nil {
			//return nil, errors.New("no valid combination found")
			continue
		}

		err = bls.Verify(suite, public.Commit(), msg, sig)

		if err == nil {
			return sig, nil
		}

	}
	return nil, errors.New("no valid combination found")
}

func recover(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte,error){
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := ths.SigShare(sig)
		point := suite.G1().Point()
		i, err := s.Index()
		if err != nil {
			return nil, err
		}
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

func NewTBLS256Optimistic() crypto.SignerVerifierAggregator {
	return &tbls{
			bn256.NewSuite(),
			recoverOptimistic,
		}
}

func NewTBLS256OptimisticCryptoHandler() crypto.THSignerHandler {
	return tblsHandler{
		NewTBLS256Optimistic(),
		NewTBLS256KeyGenerator(),
		TBLSOptimistic}
}





