package main

/*
import (
	"fmt"
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/client"
	"time"
)

func main() {
	_ = log.SetLogLevel("crypto_client", "debug")
	context , _:= client.NewCryptoFactory("tcp://127.0.0.1:9000")

	time.Sleep(10*time.Second)
	gen := context.GetKeyGenerator("TBLS256")
	sign := context.GetSignerVerifierAggregator("TBLS256")

	pub, privs := gen.Gen(10,6)

	s := make([][]byte,0)
	for _,v := range privs {
		sig, err := sign.Sign([]byte("Jorge"), v)

		if err != nil {
			fmt.Println("Error Signing")
		}
		fmt.Println(sig)

		s = append(s,sig)
	}

	aggregated,err := sign.Aggregate(s,[]byte("Jorge"),pub,10,6)

	if err != nil {
		fmt.Println("Error Aggregating")
	}
	fmt.Println(aggregated)

	err = sign.Verify(aggregated,[]byte("Jorge"),pub)

	if err != nil {
		fmt.Println("Invalid Signature")
	}

	select {

	}
}*/
