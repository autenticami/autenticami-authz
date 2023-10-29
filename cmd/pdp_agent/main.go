package main

import (
	"net"
	"os"

	cmd_pdp_apiv1 "github.com/autenticami/autenticami-authz/cmd/pdp_agent/api/v1"
	pkg_core "github.com/autenticami/autenticami-authz/pkg/core"
	pkg_pdp "github.com/autenticami/autenticami-authz/pkg/pdp_agent"
	pkg_pdp_local "github.com/autenticami/autenticami-authz/pkg/pdp_agent/local"
	
	"google.golang.org/grpc"
	log "github.com/sirupsen/logrus"
)

var config = func() pkg_core.Config {
	if pkg_pdp.EnvKeyAutenticamiAgentType == "PDP-LOCAL" {
		return pkg_pdp_local.NewLocalConfig()
	} else {
		return nil
	}
}()

func init() {
	if config.IsLocal() {
		// Log as ASCII instead of the default JSON formatter.
		log.SetFormatter(&log.TextFormatter{ForceColors: true, DisableColors: false, FullTimestamp: true})
		// Output to stdout instead of the default stderr
		log.SetOutput(os.Stdout)
		// Only log the info severity or above.
		log.SetLevel(log.InfoLevel)
	} else {
		// Log as JSON instead of the default ASCII formatter.
		log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
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

	cmd_pdp_apiv1.RegisterPDPServiceServer(s, &cmd_pdp_apiv1.PDPServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
		os.Exit(1)
	}
}
