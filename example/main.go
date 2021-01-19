package main

import (
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
)

func main() {

	_ = log.SetLogLevel("signer_processor", "debug")

	processor := crypto.NewSignerProcessor("tcp://127.0.0.1:9000")
	processor.AddHandler(tbls.NewTBLS256CryptoHandler())
	processor.Start()
}
