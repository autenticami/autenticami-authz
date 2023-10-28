package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/autenticami/autenticami-authz/cmd/pdp-agent/api/v1"
	"github.com/google/uuid"

	"google.golang.org/grpc"
)

type PermissionsServer struct {
	pb.UnimplementedPermissionsServiceServer
}

func (s *PermissionsServer) GetPermissionsState(ctx context.Context, req *pb.PermissionsStateRequest) (*pb.PermissionsStateResponse, error) {
	log.Printf("received: %v", req.Identity.GetUur())
	permissions := &pb.PermissionsStateResponse{
		Identity: &pb.Identity{
			Uur: req.Identity.GetUur(),
		},
		PermissionsState: nil,
	}

	return permissions, nil
}

func (s *PermissionsServer) EvaluatePermissions(ctx context.Context, req *pb.PermissionsEvaluationRequest) (*pb.PermissionsEvaluationResponse, error) {
	log.Printf("received: %v", req.Identity.GetUur())
	permissionsEvaluation := &pb.PermissionsEvaluationResponse{
		Identity: &pb.Identity{
			Uur: req.Identity.GetUur(),
		},
		Evaluations: make([]*pb.PermissionsEvaluationOutcome, len(req.Evaluations)),
		Allowed: true,
	}
	for i, evaluation := range req.Evaluations {
		outcome := &pb.PermissionsEvaluationOutcome{
			Evaluation: evaluation,
			Allowed: true,
			Explanation: &pb.PermissionsEvaluationOutcomeExplanation{
				IsExplicitlyDenied:  true,
				IsImplicitlyDenied:  false,
			},
		}
		outcome.Evaluation.Id = uuid.New().String()
		permissionsEvaluation.Evaluations[i] = outcome
	}
	return permissionsEvaluation, nil
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
