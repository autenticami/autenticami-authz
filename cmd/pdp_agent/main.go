package main

import (
	"net"
	"os"

	pbApiV1 "github.com/autenticami/autenticami-authz/cmd/pdp_agent/api/v1"
	pCore "github.com/autenticami/autenticami-authz/pkg/core"
	pdpConfig "github.com/autenticami/autenticami-authz/pkg/pdp_agent/local"
	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
)


func getConfig() pCore.Config {
	return pdpConfig.NewLocalConfig()
}

var localConfig = getConfig()

func init() {
	if localConfig.IsLocal() {
		// Log as ASCII instead of the default JSON formatter.
		log.SetFormatter(&log.TextFormatter{ ForceColors: true, DisableColors: false, FullTimestamp: true})
		// Output to stdout instead of the default stderr
		log.SetOutput(os.Stdout)
		// Only log the info severity or above.
		log.SetLevel(log.InfoLevel)
	} else {
		// Log as JSON instead of the default ASCII formatter.
		log.SetFormatter(&log.JSONFormatter{ PrettyPrint: true})
		// Output to stdout instead of the default stderr
		log.SetOutput(os.Stdout)
		// Only log the info severity or above.
		log.SetLevel(log.WarnLevel)
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("tcp connection failed: %v", err)
		os.Exit(1)
	}
	log.Infof("listening at %v", lis.Addr())

	s := grpc.NewServer()
	
	pbApiV1.RegisterPDPServiceServer(s, &pbApiV1.PDPServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
		os.Exit(1)
	}
}
