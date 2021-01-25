package client

import (
	"github.com/golang/protobuf/proto"
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/crypto"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
	"github.com/jffp113/CryptoProviderSDK/messaging"
	zmq "github.com/pebbe/zmq4"
)

var logger = log.Logger("crypto_client")

const RegisterChanSize = 5
const InChanSize = 5
const OutChanSize = 5

type cryptoClient struct {
	requests map[string]chan *pb.HandlerMessage
	handlers map[string]string
	registerHandlerChan chan msgWithCorrelation
	inData chan msgWithCorrelation
	outData chan msgWithCorrelationAndChan
	conn *messaging.ZmqConnection
}


type msgWithCorrelation struct {
	msg *pb.HandlerMessage
	corrId string
}

type msgWithCorrelationAndChan struct {
	msgWithCorrelation
	replyChan chan *pb.HandlerMessage
}

func NewCryptoFactory(uri string) (crypto.ContextFactory, error){
	context, _ := zmq.NewContext()

	conn, err := messaging.NewConnection(context, zmq.ROUTER, uri, true)

	if err != nil {
		return nil,err
	}

	c := cryptoClient{
		requests:            make(map[string]chan *pb.HandlerMessage),
		handlers:            make(map[string]string),
		registerHandlerChan: make(chan msgWithCorrelation, RegisterChanSize),
		inData:              make(chan msgWithCorrelation, InChanSize),
		outData:             make(chan msgWithCorrelationAndChan, OutChanSize),
		conn:                conn,
	}

	go c.receive()
	go c.processInOut()
	go c.processNewHandlers()

	return &c, nil
}

func (c *cryptoClient) Close() error{
	c.conn.Close()
	return nil
}

func (c *cryptoClient) receive() {
	for {

		corrId,data, err := c.conn.RecvData()

		if err != nil {
			logger.Warnf("Error Ignoring MSG: %v",err)
			continue
		}

		msg := pb.HandlerMessage{}

		err = proto.Unmarshal(data,&msg)

		if err != nil {
			logger.Warnf("Error Ignoring MSG: %v",err)
			continue
		}

		c.inData<-msgWithCorrelation{
			msg:    &msg,
			corrId: corrId,
		}

	}
}


func (c *cryptoClient) processInOut() {
	for{
		select {
		case data := <-c.inData:
			if data.msg.Type == pb.HandlerMessage_HANDLER_REGISTER_REQUEST{
				logger.Debug("Register msg received")
				msgCorrId := msgWithCorrelation{
					msg:  	data.msg,
					corrId: data.corrId,
				}
				c.registerHandlerChan<-msgCorrId
			} else {
				logger.Debug("Received msg")
				v,present := c.requests[data.msg.CorrelationId]
				if !present {
					logger.Warnf("MSG not expected, ignoring MSG")
					continue
				}
				v<-data.msg
				delete(c.requests, data.msg.CorrelationId)
			}
		case data := <-c.outData:
			logger.Debug("Sending msg out")

			bytes,err := proto.Marshal(data.msg)

			if err != nil {
				logger.Warnf("Error out msg: %v",err)
				continue
			}
			c.requests[data.msg.CorrelationId] = data.replyChan
			err = c.conn.SendData(data.corrId, bytes)
			logger.Debug("Sent msg out")
			if err != nil {
				logger.Warnf("Error out msg: %v",err)
				continue
			}
		}

	}
}

func (c *cryptoClient) processNewHandlers() {
	for newMsg := range c.registerHandlerChan {
		req := pb.HandlerRegisterRequest{}

		err := proto.Unmarshal(newMsg.msg.Content,&req)

		if err != nil {
			logger.Warnf("Error Ignoring register handler MSG: %v",err)
			continue
		}
		logger.Debugf("Registering %v from %v",req.Scheme,newMsg.corrId)

		c.handlers[req.Scheme] = newMsg.corrId

		rep := pb.HandlerRegisterResponse{Status: pb.HandlerRegisterResponse_OK}


		handlerMsg,_,err:= pb.CreateHandlerMessageWithCorrelationId(pb.HandlerMessage_HANDLER_REGISTER_RESPONSE,
												&rep,newMsg.msg.CorrelationId)

		if err != nil {
			logger.Warnf("Error Ignoring register handler MSG: %v",err)
			continue
		}

		c.outData<-msgWithCorrelationAndChan{
			msgWithCorrelation: msgWithCorrelation{
				msg:    handlerMsg,
				corrId: newMsg.corrId,
			},
			replyChan:          nil,
		}


	}
}




