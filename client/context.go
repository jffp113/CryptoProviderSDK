package client

import (
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
)

type context struct {
	scheme string
	client *cryptoClient
}

type privKey struct {
	content []byte
}

func (key *privKey) MarshalBinary() (data []byte, err error){
	return key.content,nil
}

type pubKey struct {
	content []byte
}

func (key *pubKey) MarshalBinary() (data []byte, err error){
	return key.content,nil
}

func (c *cryptoClient) GetSignerVerifierAggregator(cryptoId string) crypto.SignerVerifierAggregator {
	return context{cryptoId,c}
}

func (c *cryptoClient) GetKeyGenerator(cryptoId string) crypto.KeyShareGenerator {
	return context{cryptoId,c}
}

func (c context) Sign(digest []byte, key crypto.PrivateKey) (signature []byte, err error) {
	logger.Debugf("Sign Key for %v",c.scheme)
	handlerId := c.client.handlers[c.scheme]

	d,_ := key.MarshalBinary()

	req := pb.SignRequest{
		Scheme:      c.scheme,
		Digest:      digest,
		PrivateKeys: d,
	}
	msg,_,_ := pb.CreateHandlerMessage(pb.HandlerMessage_SIGN_REQUEST, &req)

	out := msgWithCorrelationAndChan{
		msgWithCorrelation: msgWithCorrelation{
			msg:    msg,
			corrId: handlerId,
		},
		replyChan:          make(chan *pb.HandlerMessage,1),
	}

	c.client.outData<-out

	reply := <-out.replyChan

	replySign := pb.SignResponse{}
	err = proto.Unmarshal(reply.Content,&replySign)

	if err != nil{
		return nil,err
	}

	if replySign.Status != pb.SignResponse_OK {
		return nil,errors.New("error signing")
	}

	return replySign.Signature,nil

}

func (c context) Verify(signature []byte, msg []byte, key crypto.PublicKey) error {
	logger.Debugf("Verify Request for %v",c.scheme)

	handlerId := c.client.handlers[c.scheme]

	keyBytes,_ := key.MarshalBinary()

	request := pb.VerifyRequest{
		Scheme:    c.scheme,
		Signature: signature,
		Msg:       msg,
		PubKey:    keyBytes,
	}

	requestMsg,_,_ := pb.CreateHandlerMessage(pb.HandlerMessage_VERIFY_REQUEST, &request)

	out := msgWithCorrelationAndChan{
		msgWithCorrelation: msgWithCorrelation{
			msg:    requestMsg,
			corrId: handlerId,
		},
		replyChan:          make(chan *pb.HandlerMessage,1),
	}

	c.client.outData<-out

	reply := <-out.replyChan

	replySign := pb.VerifyResponse{}
	_ = proto.Unmarshal(reply.Content,&replySign)

	if replySign.Status == pb.VerifyResponse_ERROR {
		return errors.New("invalid signature")
	}

	return nil
}

func (c context) Aggregate(share [][]byte, digest []byte, key crypto.PublicKey, t, n int) (signature []byte, err error) {
	logger.Debugf("Aggregating Request for %v",c.scheme)

	handlerId := c.client.handlers[c.scheme]

	keyBytes,_ := key.MarshalBinary()

	req := pb.AggregateRequest{
		Scheme: c.scheme,
		Share:  share,
		Digest: digest,
		PubKey: keyBytes,
		T:      int32(t),
		N:      int32(n),
	}

	msg,_,_ := pb.CreateHandlerMessage(pb.HandlerMessage_AGGREGATE_REQUEST, &req)

	out := msgWithCorrelationAndChan{
		msgWithCorrelation: msgWithCorrelation{
			msg:    msg,
			corrId: handlerId,
		},
		replyChan:          make(chan *pb.HandlerMessage,1),
	}

	c.client.outData<-out

	reply := <-out.replyChan

	replySign := pb.AggregateResponse{}
	err = proto.Unmarshal(reply.Content,&replySign)

	if replySign.Status == pb.AggregateResponse_ERROR {
		return nil, errors.New("error aggregating")
	}

	return replySign.Signature,nil
}

func (c context) Gen(n int, t int) (crypto.PublicKey, crypto.PrivateKeyList) {
	logger.Debugf("Requesting Key Gen for %v",c.scheme)
	handlerId := c.client.handlers[c.scheme]

	req := pb.GenerateTHSRequest{
		Scheme: c.scheme,
		T:      uint32(t),
		N:      uint32(n),
	}

	msg,_,_ := pb.CreateHandlerMessage(pb.HandlerMessage_GENERATE_THS_REQUEST, &req)

	out := msgWithCorrelationAndChan{
		msgWithCorrelation: msgWithCorrelation{
			msg:    msg,
			corrId: handlerId,
		},
		replyChan:          make(chan *pb.HandlerMessage,1),
	}


	c.client.outData<-out

	reply := <-out.replyChan

	if reply.Type != pb.HandlerMessage_GENERATE_THS_RESPONSE {
		panic("Wrong message received")
	}

	replyTHS := pb.GenerateTHSResponse{}

	err := proto.Unmarshal(reply.Content,&replyTHS)

	if err != nil {
		panic("error unmarshalling msg")
	}


	pubKey := pubKey{content: replyTHS.PublicKey}
	privKeySlice := make([]crypto.PrivateKey,len(replyTHS.PrivateKeys))

	for i,v :=  range replyTHS.PrivateKeys {
		privKeySlice[i] = &privKey{content: v}
	}

	return &pubKey, privKeySlice
}
