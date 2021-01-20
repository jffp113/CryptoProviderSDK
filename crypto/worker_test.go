package crypto

import (
	"bytes"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
	"testing"
)

//Mocks

type mockSignerHandler struct {

}

type mockPrivKey []byte
type mockPubKey []byte

func (m mockPrivKey) MarshalBinary() (data []byte, err error){
	return m , nil
}
func (m mockPubKey) MarshalBinary() (data []byte, err error){
	return m , nil
}

func (m mockSignerHandler) Gen(n int, t int) (PublicKey, PrivateKeyList) {
	l := make([]PrivateKey,n)

	for i := 1 ;i <= n; i++ {
		l[i - 1] = mockPrivKey("1")
	}

	return mockPubKey("ok"),l
}

//This mock will give a error when the digest is zero length
func (m mockSignerHandler) Sign(digest []byte, key PrivateKey) (signature []byte, err error) {
	var buff bytes.Buffer

	if len(digest) == 0{
		return nil,errors.New("Could not sign")
	}

	buff.Write(digest)
	b, _ := key.MarshalBinary()
	buff.Write(b)
	return signature,nil
}

//This mock will give a error when the PublicKey is zero length
func (m mockSignerHandler) Verify(signature []byte, msg []byte, key PublicKey) error {
	b, _ := key.MarshalBinary()

	if len(b) == 0 {
		return errors.New("invalid signature")
	}

	return nil
}

//This mock will give error if t > n
func (m mockSignerHandler) Aggregate(share [][]byte, digest []byte, key PublicKey, t, n int) (signature []byte, err error) {
	if t > n {
		return nil, errors.New("error aggregating sig")
	}
	return digest,nil
}

func (m mockSignerHandler) SchemeName() string {
	return "Mock"
}

func (m mockSignerHandler) UnmarshalPublic(data []byte) PublicKey {
	return mockPubKey(data)
}

func (m mockSignerHandler) UnmarshalPrivate(data []byte) PrivateKey {
	return mockPrivKey(data)
}

func prepareTest() (chan []byte, chan *pb.HandlerMessage) {
	handlers:= make([]THSignerHandler,0)
	handlers = append(handlers,mockSignerHandler{})

	returnChan := make(chan []byte,1)
	workerChan := make(chan *pb.HandlerMessage,1)

	go worker(returnChan,workerChan,handlers)

	return returnChan,workerChan
}

func TestVerifyWhenVerifySucceeds(test *testing.T) {
	 returnChan, workerChan := prepareTest()

	verifyReq := pb.VerifyRequest{
		Scheme:    "Mock",
		Signature: []byte{},
		Msg:       []byte{},
		PubKey:    mockPubKey("hello"),
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_VERIFY_REQUEST,&verifyReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)
	
	if responseHandlerMsg.Type != pb.HandlerMessage_VERIFY_RESPONSE {
		test.Error("Wrong message type")
	}
	if responseHandlerMsg.CorrelationId != "1" {
		test.Error("Wrong correlation ID")
	}

	verifyResponse := pb.VerifyResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&verifyResponse)

	if verifyResponse.Status != pb.VerifyResponse_OK {
		test.Error("Verification Failed")
	}
}

func TestVerifyWhenVerifyFails(test *testing.T) {
	returnChan, workerChan := prepareTest()

	verifyReq := pb.VerifyRequest{
		Scheme:    "Mock",
		Signature: []byte{},
		Msg:       []byte{},
		PubKey:    mockPubKey(""),
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_VERIFY_REQUEST,&verifyReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	verifyResponse := pb.VerifyResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&verifyResponse)

	if verifyResponse.Status != pb.VerifyResponse_ERROR {
		test.Error("Verification should not have succeeds")
	}
}

func TestSignWhenSignSucceeds(test *testing.T) {
	returnChan, workerChan := prepareTest()

	signReq := pb.SignRequest{
		Scheme:      "Mock",
		Digest:      []byte("Good digest"),
		PrivateKeys: mockPrivKey{},
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_SIGN_REQUEST,&signReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	if responseHandlerMsg.Type != pb.HandlerMessage_SIGN_RESPONSE {
		test.Error("Wrong message type")
	}
	if responseHandlerMsg.CorrelationId != "1" {
		test.Error("Wrong correlation ID")
	}

	signResponse := pb.SignResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&signResponse)

	if signResponse.Status != pb.SignResponse_OK {
		test.Error("Verification Failed")
	}
}

func TestSignWhenSignFails(test *testing.T) {
	returnChan, workerChan := prepareTest()

	signReq := pb.SignRequest{
		Scheme:      "Mock",
		Digest:      []byte(""),
		PrivateKeys: mockPrivKey{},
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_SIGN_REQUEST,&signReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	signResponse := pb.SignResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&signResponse)

	if signResponse.Status != pb.SignResponse_ERROR {
		test.Error("Verification Failed")
	}
}

func unmarshallBytesToHandlerMessage(data []byte)  *pb.HandlerMessage{
	h := pb.HandlerMessage{}
	_ = proto.Unmarshal(data, &h)
	return &h
}

func TestAggregateWhenAggregateSucceeds(test *testing.T) {
	returnChan, workerChan := prepareTest()

	aggregateReq := pb.AggregateRequest{
		Scheme: "Mock",
		Share:  nil,
		Digest: []byte("Good digest"),
		PubKey: mockPubKey{},
		T:      2,
		N:      5,
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_AGGREGATE_REQUEST,&aggregateReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	if responseHandlerMsg.Type != pb.HandlerMessage_AGGREGATE_RESPONSE {
		test.Error("Wrong message type")
	}
	if responseHandlerMsg.CorrelationId != "1" {
		test.Error("Wrong correlation ID")
	}

	aggregateResponse := pb.AggregateResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&aggregateResponse)

	if aggregateResponse.Status != pb.AggregateResponse_OK {
		test.Error("Verification Failed")
	}
}

func TestAggregateWhenAggregateFails(test *testing.T) {
	returnChan, workerChan := prepareTest()

	aggregateReq := pb.AggregateRequest{
		Scheme: "Mock",
		Share:  nil,
		Digest: []byte("Good digest"),
		PubKey: mockPubKey{},
		T:      6,
		N:      5,
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_AGGREGATE_REQUEST,&aggregateReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	aggregateResponse := pb.AggregateResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&aggregateResponse)

	if aggregateResponse.Status != pb.AggregateResponse_ERROR {
		test.Error("Verification Failed")
	}
}

func TestGenWhenGenSucceeds(test *testing.T) {
	returnChan, workerChan := prepareTest()

	genReq := pb.GenerateTHSRequest{
		Scheme: "Mock",
		T:      2,
		N:      5,
	}

	msg , _ , _ := pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_GENERATE_THS_REQUEST,&genReq,"1")
	workerChan<-msg

	responseBytes := <-returnChan

	responseHandlerMsg := unmarshallBytesToHandlerMessage(responseBytes)

	if responseHandlerMsg.Type != pb.HandlerMessage_GENERATE_THS_RESPONSE {
		test.Error("Wrong message type")
	}
	if responseHandlerMsg.CorrelationId != "1" {
		test.Error("Wrong correlation ID")
	}

	genResponse := pb.GenerateTHSResponse{}
	proto.Unmarshal(responseHandlerMsg.Content,&genResponse)

	if genResponse.Status != pb.GenerateTHSResponse_OK {
		test.Error("Verification Failed")
	}
}