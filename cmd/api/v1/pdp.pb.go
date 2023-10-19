// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: cmd/api/v1/pdp.proto

package v1

import (
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

type PermissionsSateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IdentityUUR string `protobuf:"bytes,1,opt,name=identityUUR,proto3" json:"identityUUR,omitempty"`
}

func (x *PermissionsSateRequest) Reset() {
	*x = PermissionsSateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cmd_api_v1_pdp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PermissionsSateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PermissionsSateRequest) ProtoMessage() {}

func (x *PermissionsSateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cmd_api_v1_pdp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PermissionsSateRequest.ProtoReflect.Descriptor instead.
func (*PermissionsSateRequest) Descriptor() ([]byte, []int) {
	return file_cmd_api_v1_pdp_proto_rawDescGZIP(), []int{0}
}

func (x *PermissionsSateRequest) GetIdentityUUR() string {
	if x != nil {
		return x.IdentityUUR
	}
	return ""
}

type PermissionsSate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *PermissionsSate) Reset() {
	*x = PermissionsSate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cmd_api_v1_pdp_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PermissionsSate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PermissionsSate) ProtoMessage() {}

func (x *PermissionsSate) ProtoReflect() protoreflect.Message {
	mi := &file_cmd_api_v1_pdp_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PermissionsSate.ProtoReflect.Descriptor instead.
func (*PermissionsSate) Descriptor() ([]byte, []int) {
	return file_cmd_api_v1_pdp_proto_rawDescGZIP(), []int{1}
}

func (x *PermissionsSate) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type PermissionsSateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IdentityUUR     string           `protobuf:"bytes,1,opt,name=identityUUR,proto3" json:"identityUUR,omitempty"`
	PermissionsSate *PermissionsSate `protobuf:"bytes,2,opt,name=permissionsSate,proto3,oneof" json:"permissionsSate,omitempty"`
}

func (x *PermissionsSateResponse) Reset() {
	*x = PermissionsSateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cmd_api_v1_pdp_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PermissionsSateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PermissionsSateResponse) ProtoMessage() {}

func (x *PermissionsSateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cmd_api_v1_pdp_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PermissionsSateResponse.ProtoReflect.Descriptor instead.
func (*PermissionsSateResponse) Descriptor() ([]byte, []int) {
	return file_cmd_api_v1_pdp_proto_rawDescGZIP(), []int{2}
}

func (x *PermissionsSateResponse) GetIdentityUUR() string {
	if x != nil {
		return x.IdentityUUR
	}
	return ""
}

func (x *PermissionsSateResponse) GetPermissionsSate() *PermissionsSate {
	if x != nil {
		return x.PermissionsSate
	}
	return nil
}

var File_cmd_api_v1_pdp_proto protoreflect.FileDescriptor

var file_cmd_api_v1_pdp_proto_rawDesc = []byte{
	0x0a, 0x14, 0x63, 0x6d, 0x64, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x64, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x64, 0x65,
	0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x22, 0x3a, 0x0a, 0x16, 0x50,
	0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x55, 0x55, 0x52, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x55, 0x55, 0x52, 0x22, 0x21, 0x0a, 0x0f, 0x50, 0x65, 0x72, 0x6d, 0x69,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0xa4, 0x01, 0x0a, 0x17, 0x50,
	0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x55, 0x55, 0x52, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x55, 0x55, 0x52, 0x12, 0x53, 0x0a, 0x0f, 0x70, 0x65, 0x72, 0x6d,
	0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x24, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69,
	0x6f, 0x6e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x48, 0x00, 0x52, 0x0f, 0x70, 0x65, 0x72, 0x6d, 0x69,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74, 0x65, 0x88, 0x01, 0x01, 0x42, 0x12, 0x0a,
	0x10, 0x5f, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61, 0x74,
	0x65, 0x32, 0x86, 0x01, 0x0a, 0x12, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x70, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x50,
	0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12,
	0x2b, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x53, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x53, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x35, 0x5a, 0x33, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x75, 0x74, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x6d, 0x69, 0x2f, 0x61, 0x75, 0x74, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x6d, 0x69,
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2f, 0x63, 0x6d, 0x64, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cmd_api_v1_pdp_proto_rawDescOnce sync.Once
	file_cmd_api_v1_pdp_proto_rawDescData = file_cmd_api_v1_pdp_proto_rawDesc
)

func file_cmd_api_v1_pdp_proto_rawDescGZIP() []byte {
	file_cmd_api_v1_pdp_proto_rawDescOnce.Do(func() {
		file_cmd_api_v1_pdp_proto_rawDescData = protoimpl.X.CompressGZIP(file_cmd_api_v1_pdp_proto_rawDescData)
	})
	return file_cmd_api_v1_pdp_proto_rawDescData
}

var file_cmd_api_v1_pdp_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_cmd_api_v1_pdp_proto_goTypes = []interface{}{
	(*PermissionsSateRequest)(nil),  // 0: policydecisionpoint.PermissionsSateRequest
	(*PermissionsSate)(nil),         // 1: policydecisionpoint.PermissionsSate
	(*PermissionsSateResponse)(nil), // 2: policydecisionpoint.PermissionsSateResponse
}
var file_cmd_api_v1_pdp_proto_depIdxs = []int32{
	1, // 0: policydecisionpoint.PermissionsSateResponse.permissionsSate:type_name -> policydecisionpoint.PermissionsSate
	0, // 1: policydecisionpoint.PermissionsService.GetPermissionsState:input_type -> policydecisionpoint.PermissionsSateRequest
	2, // 2: policydecisionpoint.PermissionsService.GetPermissionsState:output_type -> policydecisionpoint.PermissionsSateResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cmd_api_v1_pdp_proto_init() }
func file_cmd_api_v1_pdp_proto_init() {
	if File_cmd_api_v1_pdp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cmd_api_v1_pdp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PermissionsSateRequest); i {
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
		file_cmd_api_v1_pdp_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PermissionsSate); i {
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
		file_cmd_api_v1_pdp_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PermissionsSateResponse); i {
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
	file_cmd_api_v1_pdp_proto_msgTypes[2].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cmd_api_v1_pdp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cmd_api_v1_pdp_proto_goTypes,
		DependencyIndexes: file_cmd_api_v1_pdp_proto_depIdxs,
		MessageInfos:      file_cmd_api_v1_pdp_proto_msgTypes,
	}.Build()
	File_cmd_api_v1_pdp_proto = out.File
	file_cmd_api_v1_pdp_proto_rawDesc = nil
	file_cmd_api_v1_pdp_proto_goTypes = nil
	file_cmd_api_v1_pdp_proto_depIdxs = nil
}