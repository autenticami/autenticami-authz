package main

import (
	"net"
	"os"
	"strings"

	cmdPdpApiV1 "github.com/autenticami/autenticami-authz/cmd/pdpagent/api/v1"
	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"
	pkgPdp "github.com/autenticami/autenticami-authz/pkg/pdpagent"
	pkgPdpLocal "github.com/autenticami/autenticami-authz/pkg/pdpagent/local"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var config = func() pkgCore.Config {
	agentType := pkgCore.GetEnv(pkgPdp.EnvKeyAutenticamiAgentType, pkgPdp.AutenticamiPDPAgentTypeLocal)
	if strings.ToUpper(agentType) == "PDP-LOCAL" {
		return pkgPdpLocal.NewLocalConfig()
	}
	log.Fatalf("%s: %s is an invalid agent type", pkgPdp.EnvKeyAutenticamiAgentType, agentType)
	panic(1)
}()

func init() {
	if config.GetGoEnv() {
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
	isLocalAgent := config.GetAgentType() == pkgPdp.AutenticamiPDPAgentTypeLocal
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("tcp connection failed: %v", err)
		os.Exit(1)
	}
	log.Infof("listening at %v", lis.Addr())

	s := grpc.NewServer()

	pdpServer := &cmdPdpApiV1.PDPServer{}
	if  isLocalAgent {
		pdpServer.Service = pkgPdpLocal.NewPDPLocalService(config.(pkgPdpLocal.LocalConfig))
	} else {
		log.Fatal("PDP-REMOTE is not implemented yet")
		os.Exit(1)
	}
	pdpServer.Service.Setup()
	cmdPdpApiV1.RegisterPDPServiceServer(s, pdpServer)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
		os.Exit(1)
	}
}
