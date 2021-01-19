package crypto

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
	"github.com/jffp113/CryptoProviderSDK/messaging"
	zmq "github.com/pebbe/zmq4"
	"github.com/ipfs/go-log"
)

var logger = log.Logger("signer_processor")

const DefaultMaxWorkQueueSize = 100
const DefaultMaxWorkers = 4

type SignerProcessor struct {
	uri         string
	ids         map[string]string
	handlers    []THSignerHandler
	nThreads    uint
	maxQueue    uint
}

func NewSignerProcessor(uri string) *SignerProcessor {
	return &SignerProcessor{
		uri:      uri,
		ids:      make(map[string]string),
		handlers: make([]THSignerHandler, 0),
		nThreads: DefaultMaxWorkers,
		maxQueue: DefaultMaxWorkQueueSize,
	}
}

func (self *SignerProcessor) AddHandler(handler THSignerHandler) {
	self.handlers = append(self.handlers, handler)
}

func (self *SignerProcessor) Start() error {

	ctx, err := zmq.NewContext()
	if err != nil {
		panic(fmt.Sprint("Failed to create ZMQ context: ", err))
	}

	return self.start(ctx)
}

func (self *SignerProcessor) start(ctx *zmq.Context) error {
	logger.Info("Starting Signer Processor")
	node, err := messaging.NewConnection(ctx, zmq.DEALER, self.uri, false)

	if err != nil {
		return err
	}

	workerChan := make(chan *pb.HandlerMessage,self.maxQueue)
	returnChan := make(chan []byte,self.maxQueue)

	setupWorkers(returnChan,workerChan,self.nThreads,self.handlers)
	err = registerHandlers(node,self.handlers,workerChan)

	if err != nil {
		return err
	}

	go processIncomingMsg(node,workerChan)
	processOutgoing(node,returnChan)

	return nil
}

func setupWorkers(returnChan chan<- []byte, workerChan <-chan *pb.HandlerMessage,
	nWorkers uint,handlers []THSignerHandler  ) {
	for i := uint(0) ; i < nWorkers; i++ {
		go worker(returnChan, workerChan,handlers)
	}
}

func processOutgoing(node *messaging.ZmqConnection, returnChan <-chan []byte) {
	for msg := range returnChan{
		err := node.SendData("",msg)

		if err != nil {
			logger.Warn("Error sending data to SignerNode, ignoring msg")
		}
	}
}

func processIncomingMsg(node *messaging.ZmqConnection,workerChan chan<- *pb.HandlerMessage) {
	logger.Debug("Started Processing incoming msgs")

	for {
		_, data, err := node.RecvData()

		if err != nil {
			logger.Warn("Error receiving data from SignerNode, ignoring msg")
		}

		msg, err := pb.UnmarshallSignMessage(data)

		if err != nil {
			logger.Warn("Error unmarshalling data from SignerNode, ignoring msg")
		}

		workerChan<-msg
	}

}

func registerHandlers(node *messaging.ZmqConnection, handlers []THSignerHandler,workerChan chan<-*pb.HandlerMessage) error {

	for _,handler := range handlers{

		regRequest := &pb.HandlerRegisterRequest{
			Scheme:       handler.SchemeName(),
		}
		logger.Debugf("Registering (%v)", regRequest.Scheme)


		regRequestData, err := proto.Marshal(regRequest)

		if err != nil {
			return err
		}


		bytes,corrId,err := pb.CreateSignMessage(pb.HandlerMessage_HANDLER_REGISTER_REQUEST,regRequestData)

		if err != nil {
			return err
		}

		err = node.SendData("",bytes)

		if err != nil {
			return err
		}

		for{
			logger.Infof("Waiting for response (%v)",handler.SchemeName())
			_, data, err := node.RecvData()
			if err != nil {
				return err
			}

			msg, err := pb.UnmarshallSignMessage(data)
			if err != nil {
				return err
			}

			if msg.CorrelationId != corrId{
				workerChan<-msg
				continue
			}

			if msg.GetType() != pb.HandlerMessage_HANDLER_REGISTER_RESPONSE {
				return fmt.Errorf("received unexpected message type: %v", msg.GetType())
			}
			respMsg := pb.HandlerRegisterResponse{}
			err = proto.Unmarshal(msg.Content, &respMsg)
			if err != nil {
				return err
			}

			if respMsg.Status != pb.HandlerRegisterResponse_OK {
				return fmt.Errorf("got response: %v", respMsg.Status)
			}

			logger.Infof("Successfully registered handler (%v)",handler.SchemeName())
			break
		}


	}
	return nil
}



