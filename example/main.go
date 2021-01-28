package main

import (
	"fmt"
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/jessevdk/go-flags"
	"os"
)

type Opts struct {
	SignerNodeURL       string    `short:"u" long:"url" description:"Signer Node URL" default:"tcp://127.0.0.1:9000"`
}

func main() {
	var opts Opts

	parser := flags.NewParser(&opts, flags.Default)
	remaining, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Printf("Failed to parse args: %v\n", err)
			os.Exit(2)
		}
	}

	if len(remaining) > 0 {
		fmt.Printf("Error: Unrecognized arguments passed: %v\n", remaining)
		os.Exit(2)
	}


	_ = log.SetLogLevel("signer_processor", "debug")

	processor := crypto.NewSignerProcessor(opts.SignerNodeURL)
	processor.AddHandler(tbls.NewTBLS256CryptoHandler())
	processor.Start()
}
