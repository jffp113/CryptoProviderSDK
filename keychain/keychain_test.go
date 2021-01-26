package keychain

import (
	"fmt"
	"github.com/jffp113/CryptoProviderSDK/example/handlers/tbls"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)


func TestKeychain_StoreLoadKeys(test *testing.T) {
	dir, err := ioutil.TempDir("test", "keystore")
	assert.Nil(test,err)

	dir = dir + "/"
	defer os.RemoveAll(dir)

	ks := NewKeyChain(dir)
	n,t := 5,3

	gen := tbls.NewTBLS256KeyGenerator()
	pub, _ := gen.Gen(n,t)


	keyName := fmt.Sprintf("TBLS_%v_%v",n,t)
	err = ks.StorePublicKey(keyName,pub)

	keyKS,err := ks.LoadPublicKey(keyName)
	assert.Nil(test,err)

	_,err = ks.LoadPrivateKey(keyName)
	assert.NotNil(test,err)

	b,err := pub.MarshalBinary()

	assert.Equal(test,keyKS,key(b))

	assert.Nil(test,err)
}
