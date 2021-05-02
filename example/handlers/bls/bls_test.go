package rsa

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	s := NewBLS256Handler()
	public,private := s.Gen(0,0)
	sig, err := s.Sign(msg, private[0])
	require.Nil(t, err)
	err = s.Verify(sig,msg, public)
	require.Nil(t, err)
}


func TestMarshallUnmarshallKeys(t *testing.T) {

	msg := []byte("Hello Boneh-Lynn-Shacham")
	s := NewBLS256Handler()
	public,private := s.Gen(0,0)

	bytePubKey,err := public.MarshalBinary()
	assert.Nil(t,err)
	bytePrivKey,err := private[0].MarshalBinary()
	assert.Nil(t,err)

	public = s.UnmarshalPublic(bytePubKey)
	private[0] = s.UnmarshalPrivate(bytePrivKey)

	sig, err := s.Sign(msg, private[0])
	require.Nil(t, err)
	err = s.Verify(sig,msg, public)
	require.Nil(t, err)
}
