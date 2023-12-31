// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.4
// source: internal/api/pdp/v1/pdp.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	PDPService_GetPermissionsState_FullMethodName = "/policydecisionpoint.PDPService/GetPermissionsState"
	PDPService_EvaluatePermissions_FullMethodName = "/policydecisionpoint.PDPService/EvaluatePermissions"
)

// PDPServiceClient is the client API for PDPService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PDPServiceClient interface {
	GetPermissionsState(ctx context.Context, in *PermissionsStateRequest, opts ...grpc.CallOption) (*PermissionsStateResponse, error)
	EvaluatePermissions(ctx context.Context, in *PermissionsEvaluationRequest, opts ...grpc.CallOption) (*PermissionsEvaluationResponse, error)
}

type pDPServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPDPServiceClient(cc grpc.ClientConnInterface) PDPServiceClient {
	return &pDPServiceClient{cc}
}

func (c *pDPServiceClient) GetPermissionsState(ctx context.Context, in *PermissionsStateRequest, opts ...grpc.CallOption) (*PermissionsStateResponse, error) {
	out := new(PermissionsStateResponse)
	err := c.cc.Invoke(ctx, PDPService_GetPermissionsState_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pDPServiceClient) EvaluatePermissions(ctx context.Context, in *PermissionsEvaluationRequest, opts ...grpc.CallOption) (*PermissionsEvaluationResponse, error) {
	out := new(PermissionsEvaluationResponse)
	err := c.cc.Invoke(ctx, PDPService_EvaluatePermissions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PDPServiceServer is the server API for PDPService service.
// All implementations must embed UnimplementedPDPServiceServer
// for forward compatibility
type PDPServiceServer interface {
	GetPermissionsState(context.Context, *PermissionsStateRequest) (*PermissionsStateResponse, error)
	EvaluatePermissions(context.Context, *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error)
	mustEmbedUnimplementedPDPServiceServer()
}

// UnimplementedPDPServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPDPServiceServer struct {
}

func (UnimplementedPDPServiceServer) GetPermissionsState(context.Context, *PermissionsStateRequest) (*PermissionsStateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPermissionsState not implemented")
}
func (UnimplementedPDPServiceServer) EvaluatePermissions(context.Context, *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EvaluatePermissions not implemented")
}
func (UnimplementedPDPServiceServer) mustEmbedUnimplementedPDPServiceServer() {}

// UnsafePDPServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PDPServiceServer will
// result in compilation errors.
type UnsafePDPServiceServer interface {
	mustEmbedUnimplementedPDPServiceServer()
}

func RegisterPDPServiceServer(s grpc.ServiceRegistrar, srv PDPServiceServer) {
	s.RegisterService(&PDPService_ServiceDesc, srv)
}

func _PDPService_GetPermissionsState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermissionsStateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PDPServiceServer).GetPermissionsState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PDPService_GetPermissionsState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PDPServiceServer).GetPermissionsState(ctx, req.(*PermissionsStateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PDPService_EvaluatePermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermissionsEvaluationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PDPServiceServer).EvaluatePermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PDPService_EvaluatePermissions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PDPServiceServer).EvaluatePermissions(ctx, req.(*PermissionsEvaluationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PDPService_ServiceDesc is the grpc.ServiceDesc for PDPService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PDPService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policydecisionpoint.PDPService",
	HandlerType: (*PDPServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPermissionsState",
			Handler:    _PDPService_GetPermissionsState_Handler,
		},
		{
			MethodName: "EvaluatePermissions",
			Handler:    _PDPService_EvaluatePermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal/api/pdp/v1/pdp.proto",
}
