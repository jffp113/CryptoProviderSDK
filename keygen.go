package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/trsa"
	"github.com/jffp113/CryptoProviderSDK/keychain"
	"os"
)

type Opts struct {
	//Verbose []bool `short:"v" long:"verbose" description:"Increase verbosity"`
	T       int    `short:"t" long:"threshold" description:"Low limit of necessary signatures" default:"3"`
	N       int    `short:"n" long:"shares" description:"Number of shares" default:"5"`
	GenPath     string  `short:"p" long:"path" description:"Key Generation Path" default:"./resources/keys/"`
	Scheme      string `short:"s" long:"scheme" description:"Scheme" default:"TBLS256"`
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
	keyName := fmt.Sprintf("%v_%v_%v",opts.Scheme,opts.N,opts.T)

	keygen := getKeyGen(opts.Scheme)

	pub, priv := keygen.Gen(opts.N,opts.T)



	for i := 1 ; i <= opts.N ; i++{
		path := fmt.Sprintf("%v/%v/",opts.GenPath,i)
		os.MkdirAll(path , os.ModePerm)
		keychain := keychain.NewKeyChain(path)
		err := keychain.StorePublicKey(keyName,pub)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = keychain.StorePrivateKey(keyName,priv[i - 1])
		if err != nil {
			fmt.Println(err)
			return
		}
	}



}

func getKeyGen(scheme string) crypto.KeyShareGenerator {
	switch scheme {
	case "TBLS256": return tbls.NewTBLS256KeyGenerator()
	case "TRSA1024": return trsa.NewTRSAKeyGenerator()
	default:
		return nil
	}
}