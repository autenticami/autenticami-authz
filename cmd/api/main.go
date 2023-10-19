package main

import (
	"context"
	"log"
	"net"
   
	pb "github.com/autenticami/autenticami-authz/cmd/api/v1"
   
	"google.golang.org/grpc"
   )
   
   type PermissionsServer struct {
	pb.UnimplementedPermissionsServiceServer
   }
   
   func (s *PermissionsServer) GetPermissionsState(ctx context.Context, req *pb.PermissionsSateRequest) (*pb.PermissionsSateResponse, error) {
	log.Printf("received: %v", req.GetIdentityUUR())
	permissions := &pb.PermissionsSateResponse{
	 IdentityUUR:        req.GetIdentityUUR(),
	 PermissionsSate: nil,
	}
   
	return permissions, nil
   }
   
   func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
	 log.Fatalf("tcp connection failed: %v", err)
	}
	log.Printf("listening at %v", lis.Addr())
   
	s := grpc.NewServer()
   
	pb.RegisterPermissionsServiceServer(s, &PermissionsServer{})
	if err := s.Serve(lis); err != nil {
	 log.Fatalf("grpc server failed: %v", err)
	}
   }