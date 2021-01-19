package pb

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	uuid "github.com/satori/go.uuid"
)

// Generate a new UUID
func GenerateId() string {
	return fmt.Sprint(uuid.NewV4())
}

func CreateSignMessage(msgType HandlerMessage_Type, data []byte) ([]byte, string , error){
	corrId := GenerateId()
	return CreateSignMessageWithCorrelationId(msgType,data,corrId)
}

func CreateSignMessageWithCorrelationId(msgType HandlerMessage_Type, data []byte, corrId string) ([]byte, string , error){
	b,err := proto.Marshal(&HandlerMessage{
		Type:          msgType,
		CorrelationId: corrId,
		Content:       data,
	})
	return b,corrId,err
}

func CreateHandlerMessageWithCorrelationId(msgType HandlerMessage_Type, data proto.Message, corrId string) (*HandlerMessage, string , error){
	bytes,err := proto.Marshal(data)

	if err != nil {
		return nil,"",err
	}

	hd := HandlerMessage{
		Type:          msgType,
		CorrelationId: corrId,
		Content:       bytes,
	}
	return &hd,corrId,nil
}

func CreateHandlerMessage(msgType HandlerMessage_Type, data proto.Message) (*HandlerMessage, string , error){
	return CreateHandlerMessageWithCorrelationId(msgType,data,GenerateId())
}


func UnmarshallSignMessage(data []byte) (*HandlerMessage , error){
	msg := HandlerMessage{}

	err := proto.Unmarshal(data,&msg)

	return &msg,err
}