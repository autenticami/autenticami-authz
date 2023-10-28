package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/autenticami/autenticami-authz/cmd/pdp-agent/api/v1"

	"google.golang.org/grpc"
)

type PermissionsServer struct {
	pb.UnimplementedPermissionsServiceServer
}

func (s *PermissionsServer) GetPermissionsState(ctx context.Context, req *pb.PermissionsStateRequest) (*pb.PermissionsStateResponse, error) {
	log.Printf("received: %v", req.GetIdentityUUR())
	permissions := &pb.PermissionsStateResponse{
		IdentityUUR:      req.GetIdentityUUR(),
		PermissionsState: nil,
	}

	return permissions, nil
}

func (s *PermissionsServer) CheckPermissions(ctx context.Context, req *pb.CheckPermissionsRequest) (*pb.CheckPermissionsResponse, error) {
	log.Printf("received: %v", req.GetIdentityUUR())
	permissions := &pb.CheckPermissionsResponse{
		IdentityUUR:      req.GetIdentityUUR(),
		Responses: []*pb.PermissionsResponse {},
		Allowed: true,
	}

	return permissions, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("tcp connection failed: %v", err)
	}
	log.Printf("listening at %v", lis.Addr())

	dataFolder := getEnv("AUTENTICAMI_PDP_DATA", ".")
	files, err := os.ReadDir(dataFolder)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println(file.Name(), file.IsDir())
	}

	s := grpc.NewServer()

	pb.RegisterPermissionsServiceServer(s, &PermissionsServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
	}
}
