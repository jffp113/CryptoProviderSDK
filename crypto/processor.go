package crypto

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/ipfs/go-log"
	"github.com/jffp113/CryptoProviderSDK/crypto/pb"
	"github.com/jffp113/CryptoProviderSDK/messaging"
	zmq "github.com/pebbe/zmq4"
)

var logger = log.Logger("signer_processor")

const DefaultMaxWorkQueueSize = 100
const DefaultMaxWorkers = 10

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

	workers, err := messaging.NewConnection(ctx, zmq.ROUTER, "inproc://workers", true)

	if err != nil {
		return err
	}


	workerChan := make(chan *pb.HandlerMessage,self.maxQueue)

	setupWorkers("inproc://workers",ctx,workerChan,self.nThreads,self.handlers)
	err = registerHandlers(node,self.handlers,workerChan)

	if err != nil {
		return err
	}

	processOutgoingAndIncoming(node,workers,workerChan)
	return nil
}

func processOutgoingAndIncoming(node *messaging.ZmqConnection, workers *messaging.ZmqConnection, workerChan chan<- *pb.HandlerMessage) {
	poller := zmq.NewPoller()
	poller.Add(node.Socket(),zmq.POLLIN)
	poller.Add(workers.Socket(),zmq.POLLIN)

	for {
		polled, err := poller.Poll(-1)
		if err != nil {
			logger.Error("Error Polling messages from socket")
			return
		}
		for _, ready := range polled {
			switch socket := ready.Socket; socket {
			case node.Socket():
				receiveMessageFromSignerNode(node,workerChan)
			case workers.Socket():
				receiveMessageFromWorkers(workers,node)
			}
		}
	}
}

func receiveMessageFromWorkers(workers *messaging.ZmqConnection, node *messaging.ZmqConnection) {
	logger.Debug("Receiving Message from Worker")
	_, msg, err := workers.RecvData()

	err = node.SendData("",msg)

	logger.Debug("Message Sent To Signer Node")

	if err != nil {
		logger.Error("Error sending data to SignerNode, ignoring msg")
	}
}

func receiveMessageFromSignerNode(node *messaging.ZmqConnection, workerChan chan<- *pb.HandlerMessage) {
	logger.Debug("Message Signer Node")
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


func setupWorkers(workerPoolURL string,ctx *zmq.Context, workerChan <-chan *pb.HandlerMessage,
	nWorkers uint,handlers []THSignerHandler  ) {
	for i := uint(0) ; i < nWorkers; i++ {
		go worker(workerPoolURL,ctx,workerChan,handlers)
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
			logger.Infof("Waiting for response (%v)", handler.SchemeName())
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



