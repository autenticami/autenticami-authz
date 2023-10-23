// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.4
// source: cmd/agent/v1/pdp.proto

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
	PermissionsService_GetPermissionsState_FullMethodName = "/policydecisionpoint.PermissionsService/GetPermissionsState"
)

// PermissionsServiceClient is the client API for PermissionsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PermissionsServiceClient interface {
	GetPermissionsState(ctx context.Context, in *PermissionsSateRequest, opts ...grpc.CallOption) (*PermissionsSateResponse, error)
}

type permissionsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPermissionsServiceClient(cc grpc.ClientConnInterface) PermissionsServiceClient {
	return &permissionsServiceClient{cc}
}

func (c *permissionsServiceClient) GetPermissionsState(ctx context.Context, in *PermissionsSateRequest, opts ...grpc.CallOption) (*PermissionsSateResponse, error) {
	out := new(PermissionsSateResponse)
	err := c.cc.Invoke(ctx, PermissionsService_GetPermissionsState_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PermissionsServiceServer is the server API for PermissionsService service.
// All implementations must embed UnimplementedPermissionsServiceServer
// for forward compatibility
type PermissionsServiceServer interface {
	GetPermissionsState(context.Context, *PermissionsSateRequest) (*PermissionsSateResponse, error)
	mustEmbedUnimplementedPermissionsServiceServer()
}

// UnimplementedPermissionsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPermissionsServiceServer struct {
}

func (UnimplementedPermissionsServiceServer) GetPermissionsState(context.Context, *PermissionsSateRequest) (*PermissionsSateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPermissionsState not implemented")
}
func (UnimplementedPermissionsServiceServer) mustEmbedUnimplementedPermissionsServiceServer() {}

// UnsafePermissionsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PermissionsServiceServer will
// result in compilation errors.
type UnsafePermissionsServiceServer interface {
	mustEmbedUnimplementedPermissionsServiceServer()
}

func RegisterPermissionsServiceServer(s grpc.ServiceRegistrar, srv PermissionsServiceServer) {
	s.RegisterService(&PermissionsService_ServiceDesc, srv)
}

func _PermissionsService_GetPermissionsState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PermissionsSateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PermissionsServiceServer).GetPermissionsState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PermissionsService_GetPermissionsState_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PermissionsServiceServer).GetPermissionsState(ctx, req.(*PermissionsSateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PermissionsService_ServiceDesc is the grpc.ServiceDesc for PermissionsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PermissionsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policydecisionpoint.PermissionsService",
	HandlerType: (*PermissionsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPermissionsState",
			Handler:    _PermissionsService_GetPermissionsState_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cmd/agent/v1/pdp.proto",
}
