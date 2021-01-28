package crypto

import (
	"github.com/golang/protobuf/proto"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
	"github.com/jffp113/CryptoProviderSDK/messaging"
	zmq "github.com/pebbe/zmq4"
)

func worker(workerPoolURL string , context *zmq.Context, workerChan <-chan *pb.HandlerMessage, handlers []THSignerHandler) {
	connection, err := messaging.NewConnection(context, zmq.DEALER, workerPoolURL, false)
	defer connection.Close()

	if err != nil {
		logger.Error("Worker connection is nill")
		panic(err)
		return
	}

	for msg := range workerChan{
		switch msg.Type {
			case pb.HandlerMessage_SIGN_REQUEST: err = connection.SendData("",sign(msg,handlers))
			case pb.HandlerMessage_VERIFY_REQUEST: err = connection.SendData("",verify(msg,handlers))
			case pb.HandlerMessage_AGGREGATE_REQUEST: err = connection.SendData("",aggregate(msg,handlers))
			case pb.HandlerMessage_GENERATE_THS_REQUEST: err = connection.SendData("",generateTHS(msg,handlers))
		}
	}

	if err != nil {
		logger.Error("Error sending message")
	}
}

func generateTHS(msg *pb.HandlerMessage,handlers []THSignerHandler) []byte{
	logger.Debugf("Generating THS keys")
	req := pb.GenerateTHSRequest{}
	err := proto.Unmarshal(msg.Content,&req)

	if err != nil {
		logger.Warnf("Ignoring message with correlation id %v",msg.CorrelationId)
		return createGenTHSErrorMsg(msg.CorrelationId)
	}
	handler := findHandler(handlers,req.Scheme)

	pub, priv := handler.Gen(int(req.N),int(req.T))

	pubBytes,err := pub.MarshalBinary()

	if err != nil {
		logger.Warn("Error marshalling pubkey")
		return createGenTHSErrorMsg(msg.CorrelationId)
	}

	privBytes,err := priv.MarshalBinary()

	resp := pb.GenerateTHSResponse{
		Status:      pb.GenerateTHSResponse_OK,
		PublicKey:   pubBytes,
		PrivateKeys: privBytes,
	}

	msgBytes, err := proto.Marshal(&resp)

	if err != nil {
		logger.Warn("Error marshalling answer")
		return createGenTHSErrorMsg(msg.CorrelationId)
	}

	payload,_,err := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_GENERATE_THS_RESPONSE,
														msgBytes,msg.CorrelationId)

	if err != nil {
		logger.Warn("Error creating response message")
		return createGenTHSErrorMsg(msg.CorrelationId)
	}

	logger.Debugf("Finished Generating THS keys")
	return payload
}

func createGenTHSErrorMsg(corrId string) []byte{
	resp := pb.GenerateTHSResponse{
		Status:      pb.GenerateTHSResponse_ERROR,
	}

	msgBytes, _ := proto.Marshal(&resp)

	payload,_,_ := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_GENERATE_THS_RESPONSE,
		msgBytes,corrId)

	return payload
}

func aggregate(msg *pb.HandlerMessage,handlers []THSignerHandler) []byte{
	req := pb.AggregateRequest{}
	err := proto.Unmarshal(msg.Content,&req)
	logger.Debug("Start Aggregating")
	if err != nil{
		logger.Warn("Error unmarshalling request")
		return createAggregateTHSErrorMsg(msg.CorrelationId)
	}

	handler := findHandler(handlers,req.Scheme)

	pubKey := handler.UnmarshalPublic(req.PubKey)

	sig, err := handler.Aggregate(req.Share,req.Digest,pubKey,int(req.T),int(req.N))


	if err != nil {
		logger.Warn("Error generating aggregated signature")
		return createAggregateTHSErrorMsg(msg.CorrelationId)
	}

	resp := pb.AggregateResponse{
		Status:    pb.AggregateResponse_OK,
		Signature: sig,
	}

	msgBytes, err := proto.Marshal(&resp)

	if err != nil {
		logger.Warn("Error marshalling answer")
		return createAggregateTHSErrorMsg(msg.CorrelationId)
	}

	payload,_,err := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_AGGREGATE_RESPONSE,
		msgBytes,msg.CorrelationId)

	if err != nil {
		logger.Warn("Error creating response message")
		return createAggregateTHSErrorMsg(msg.CorrelationId)
	}

	logger.Debug("End Aggregating")

	return payload
}

func createAggregateTHSErrorMsg(corrId string) []byte{
	resp := pb.AggregateResponse{
		Status:      pb.AggregateResponse_ERROR,
	}

	msgBytes, _ := proto.Marshal(&resp)

	payload,_,_ := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_AGGREGATE_RESPONSE,
		msgBytes,corrId)

	return payload
}

func verify(msg *pb.HandlerMessage,handlers []THSignerHandler) []byte{
	req := pb.VerifyRequest{}
	err := proto.Unmarshal(msg.Content,&req)

	if err != nil{
		logger.Warn("Error marshalling pubkey")
		return createsVerifyTHSErrorMsg(msg.CorrelationId)
	}

	handler := findHandler(handlers,req.Scheme)

	pub := handler.UnmarshalPublic(req.PubKey)

	err = handler.Verify(req.Signature,req.Msg,pub)

	if err != nil{
		logger.Debug("Invalid Signature")
		return createsVerifyTHSErrorMsg(msg.CorrelationId)
	}

	resp := pb.VerifyResponse{
		Status:    pb.VerifyResponse_OK,
	}

	msgBytes, err := proto.Marshal(&resp)

	if err != nil{
		logger.Warn("Error marshalling response")
		return createsVerifyTHSErrorMsg(msg.CorrelationId)
	}

	payload,_,err := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_VERIFY_RESPONSE,
		msgBytes,msg.CorrelationId)

	if err != nil {
		logger.Warn("Error creating response message")
		return createAggregateTHSErrorMsg(msg.CorrelationId)
	}

	return payload
}

func createsVerifyTHSErrorMsg(corrId string) []byte{
	resp := pb.VerifyResponse{
		Status:      pb.VerifyResponse_ERROR,
	}

	msgBytes, _ := proto.Marshal(&resp)

	payload,_,_ := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_VERIFY_RESPONSE,
		msgBytes,corrId)

	return payload
}

func sign(msg *pb.HandlerMessage,handlers []THSignerHandler) []byte{
	req := pb.SignRequest{}
	err := proto.Unmarshal(msg.Content,&req)

	logger.Debug("Start Signing")

	if err != nil {
		logger.Warnf("Ignoring message with correlation id %v",msg.CorrelationId)
		return createsSignTHSErrorMsg(msg.CorrelationId)
	}

	handler := findHandler(handlers,req.Scheme)

	priv := handler.UnmarshalPrivate(req.PrivateKeys)

	data,err := handler.Sign(req.Digest,priv)

	if err != nil {
		logger.Warn("Error marshalling pubkey")
		return createsSignTHSErrorMsg(msg.CorrelationId)
	}

	resp := pb.SignResponse{
		Status:    pb.SignResponse_OK,
		Signature: data,
	}

	msgBytes, err := proto.Marshal(&resp)

	if err != nil {
		logger.Warn("Error marshalling msgBytes")
		return createsSignTHSErrorMsg(msg.CorrelationId)
	}

	payload,_,err := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_SIGN_RESPONSE,
		msgBytes,msg.CorrelationId)

	if err != nil {
		logger.Warn("Error creating response message")
		return createsSignTHSErrorMsg(msg.CorrelationId)
	}

	logger.Debug("End signing")

	return payload
}

func createsSignTHSErrorMsg(corrId string) []byte{
	resp := pb.SignResponse{
		Status:      pb.SignResponse_ERROR,
	}

	msgBytes, _ := proto.Marshal(&resp)

	payload,_,_ := pb.CreateSignMessageWithCorrelationId(pb.HandlerMessage_SIGN_RESPONSE,
		msgBytes,corrId)

	return payload
}

func findHandler(handlers []THSignerHandler,scheme string) THSignerHandler{

	for _,handler := range handlers {
		if handler.SchemeName() == scheme{
			return handler
		}
	}

	return nil
}

