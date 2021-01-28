package client

import (
	bytes2 "bytes"
	"encoding/json"
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
	workers, err := messaging.NewConnection(context, zmq.ROUTER, "inproc://workers", true)
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

	go c.receive(workers)
	go c.processInOut(context)
	go c.processNewHandlers()

	/*go func(){
		for{
			time.Sleep(10*time.Second)
			for _,v := range c.requests{
				//fmt.Println(v)
				if v != nil {
					fmt.Println(len(v))
				}
			}
		}
	}()*/

	return &c, nil
}

func (c *cryptoClient) Close() error{
	c.conn.Close()
	return nil
}

func (c *cryptoClient) receive(workers *messaging.ZmqConnection) {


	poller := zmq.NewPoller()

	poller.Add(c.conn.Socket(),zmq.POLLIN)
	poller.Add(workers.Socket(),zmq.POLLIN)

	for {
		polled, err := poller.Poll(-1)
		if err != nil {
			logger.Error("Error Polling messages from socket")
			return
		}
		for _, ready := range polled {
			switch socket := ready.Socket; socket {
			case c.conn.Socket():
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

			case workers.Socket():
				logger.Debug("Received data")
				_,data, err := workers.RecvData()

				msg := transfer{}

				reader := bytes2.NewReader(data)
				dec := json.NewDecoder(reader)
				dec.Decode(&msg)



				err = c.conn.SendData(msg.CorrId, msg.Data)
				logger.Debug("Sent msg out to signer")
				if err != nil {
					logger.Warnf("Error out msg: %v",err)
					continue
				}

			}
		}
	}

}

type transfer struct {
	Data []byte
	CorrId string
}

func (c *cryptoClient) processInOut(context *zmq.Context) {
	workers, err := messaging.NewConnection(context, zmq.DEALER, "inproc://workers", false)

	if err != nil {
		logger.Error("Error")
		return
	}

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

			tr := transfer{
				Data:   bytes,
				CorrId: data.corrId,
			}

			var buffer bytes2.Buffer
			enc := json.NewEncoder(&buffer)

			enc.Encode(&tr)

			logger.Debug(data)
			c.requests[data.msg.CorrelationId] = data.replyChan


			err = workers.SendData("", buffer.Bytes())
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




