// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.13.0
// source: message.proto

package pb

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type HandlerMessage_Type int32

const (
	HandlerMessage_DEFAULT                   HandlerMessage_Type = 0
	HandlerMessage_HANDLER_REGISTER_REQUEST  HandlerMessage_Type = 1
	HandlerMessage_HANDLER_REGISTER_RESPONSE HandlerMessage_Type = 2
	HandlerMessage_SIGN_REQUEST              HandlerMessage_Type = 100
	HandlerMessage_SIGN_RESPONSE             HandlerMessage_Type = 101
	HandlerMessage_VERIFY_REQUEST            HandlerMessage_Type = 200
	HandlerMessage_VERIFY_RESPONSE           HandlerMessage_Type = 201
	HandlerMessage_AGGREGATE_REQUEST         HandlerMessage_Type = 300
	HandlerMessage_AGGREGATE_RESPONSE        HandlerMessage_Type = 301
	HandlerMessage_GENERATE_THS_REQUEST      HandlerMessage_Type = 400
	HandlerMessage_GENERATE_THS_RESPONSE     HandlerMessage_Type = 401
)

// Enum value maps for HandlerMessage_Type.
var (
	HandlerMessage_Type_name = map[int32]string{
		0:   "DEFAULT",
		1:   "HANDLER_REGISTER_REQUEST",
		2:   "HANDLER_REGISTER_RESPONSE",
		100: "SIGN_REQUEST",
		101: "SIGN_RESPONSE",
		200: "VERIFY_REQUEST",
		201: "VERIFY_RESPONSE",
		300: "AGGREGATE_REQUEST",
		301: "AGGREGATE_RESPONSE",
		400: "GENERATE_THS_REQUEST",
		401: "GENERATE_THS_RESPONSE",
	}
	HandlerMessage_Type_value = map[string]int32{
		"DEFAULT":                   0,
		"HANDLER_REGISTER_REQUEST":  1,
		"HANDLER_REGISTER_RESPONSE": 2,
		"SIGN_REQUEST":              100,
		"SIGN_RESPONSE":             101,
		"VERIFY_REQUEST":            200,
		"VERIFY_RESPONSE":           201,
		"AGGREGATE_REQUEST":         300,
		"AGGREGATE_RESPONSE":        301,
		"GENERATE_THS_REQUEST":      400,
		"GENERATE_THS_RESPONSE":     401,
	}
)

func (x HandlerMessage_Type) Enum() *HandlerMessage_Type {
	p := new(HandlerMessage_Type)
	*p = x
	return p
}

func (x HandlerMessage_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HandlerMessage_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_message_proto_enumTypes[0].Descriptor()
}

func (HandlerMessage_Type) Type() protoreflect.EnumType {
	return &file_message_proto_enumTypes[0]
}

func (x HandlerMessage_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HandlerMessage_Type.Descriptor instead.
func (HandlerMessage_Type) EnumDescriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{0, 0}
}

type HandlerMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type          HandlerMessage_Type `protobuf:"varint,1,opt,name=type,proto3,enum=HandlerMessage_Type" json:"type,omitempty"`
	CorrelationId string              `protobuf:"bytes,2,opt,name=correlation_id,json=correlationId,proto3" json:"correlation_id,omitempty"`
	Content       []byte              `protobuf:"bytes,4,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *HandlerMessage) Reset() {
	*x = HandlerMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HandlerMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HandlerMessage) ProtoMessage() {}

func (x *HandlerMessage) ProtoReflect() protoreflect.Message {
	mi := &file_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HandlerMessage.ProtoReflect.Descriptor instead.
func (*HandlerMessage) Descriptor() ([]byte, []int) {
	return file_message_proto_rawDescGZIP(), []int{0}
}

func (x *HandlerMessage) GetType() HandlerMessage_Type {
	if x != nil {
		return x.Type
	}
	return HandlerMessage_DEFAULT
}

func (x *HandlerMessage) GetCorrelationId() string {
	if x != nil {
		return x.CorrelationId
	}
	return ""
}

func (x *HandlerMessage) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

var File_message_proto protoreflect.FileDescriptor

var file_message_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x86, 0x03, 0x0a, 0x0e, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x28, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x14, 0x2e, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x25, 0x0a, 0x0e,
	0x63, 0x6f, 0x72, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x6f, 0x72, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x49, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x88, 0x02,
	0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c,
	0x54, 0x10, 0x00, 0x12, 0x1c, 0x0a, 0x18, 0x48, 0x41, 0x4e, 0x44, 0x4c, 0x45, 0x52, 0x5f, 0x52,
	0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10,
	0x01, 0x12, 0x1d, 0x0a, 0x19, 0x48, 0x41, 0x4e, 0x44, 0x4c, 0x45, 0x52, 0x5f, 0x52, 0x45, 0x47,
	0x49, 0x53, 0x54, 0x45, 0x52, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0x02,
	0x12, 0x10, 0x0a, 0x0c, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54,
	0x10, 0x64, 0x12, 0x11, 0x0a, 0x0d, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f,
	0x4e, 0x53, 0x45, 0x10, 0x65, 0x12, 0x13, 0x0a, 0x0e, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0x5f,
	0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0xc8, 0x01, 0x12, 0x14, 0x0a, 0x0f, 0x56, 0x45,
	0x52, 0x49, 0x46, 0x59, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0xc9, 0x01,
	0x12, 0x16, 0x0a, 0x11, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x45, 0x5f, 0x52, 0x45,
	0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0xac, 0x02, 0x12, 0x17, 0x0a, 0x12, 0x41, 0x47, 0x47, 0x52,
	0x45, 0x47, 0x41, 0x54, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0xad,
	0x02, 0x12, 0x19, 0x0a, 0x14, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x45, 0x5f, 0x54, 0x48,
	0x53, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x90, 0x03, 0x12, 0x1a, 0x0a, 0x15,
	0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x45, 0x5f, 0x54, 0x48, 0x53, 0x5f, 0x52, 0x45, 0x53,
	0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0x91, 0x03, 0x42, 0x1d, 0x0a, 0x15, 0x73, 0x61, 0x77, 0x74,
	0x6f, 0x6f, 0x74, 0x68, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x50, 0x01, 0x5a, 0x02, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_message_proto_rawDescOnce sync.Once
	file_message_proto_rawDescData = file_message_proto_rawDesc
)

func file_message_proto_rawDescGZIP() []byte {
	file_message_proto_rawDescOnce.Do(func() {
		file_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_message_proto_rawDescData)
	})
	return file_message_proto_rawDescData
}

var file_message_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_message_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_message_proto_goTypes = []interface{}{
	(HandlerMessage_Type)(0), // 0: HandlerMessage.Type
	(*HandlerMessage)(nil),   // 1: HandlerMessage
}
var file_message_proto_depIdxs = []int32{
	0, // 0: HandlerMessage.type:type_name -> HandlerMessage.Type
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_message_proto_init() }
func file_message_proto_init() {
	if File_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HandlerMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_message_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_message_proto_goTypes,
		DependencyIndexes: file_message_proto_depIdxs,
		EnumInfos:         file_message_proto_enumTypes,
		MessageInfos:      file_message_proto_msgTypes,
	}.Build()
	File_message_proto = out.File
	file_message_proto_rawDesc = nil
	file_message_proto_goTypes = nil
	file_message_proto_depIdxs = nil
}
