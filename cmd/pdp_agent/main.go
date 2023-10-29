package main

import (
	"net"
	"os"

	pbApiV1 "github.com/autenticami/autenticami-authz/cmd/pdp_agent/api/v1"
	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
)

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	log.SetOutput(os.Stdout)

	// Only log the info severity or above.
	log.SetLevel(log.InfoLevel)
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("tcp connection failed: %v", err)
	}
	log.Printf("listening at %v", lis.Addr())

	// dataFolder := getEnv("AUTENTICAMI_PDP_DATA", ".")
	// files, err := os.ReadDir(dataFolder)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _, file := range files {
	// 	fmt.Println(file.Name(), file.IsDir())
	// }

	s := grpc.NewServer()

	pbApiV1.RegisterPDPServiceServer(s, &pbApiV1.PDPServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
	}
}
