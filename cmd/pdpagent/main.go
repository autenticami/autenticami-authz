package main

import (
	"net"
	"os"
	"strings"

	cmdPdpApiV1 "github.com/autenticami/autenticami-authz/cmd/pdpagent/api/v1"
	pkgAgentsCore "github.com/autenticami/autenticami-authz/pkg/agents/core"
	pkgPdp "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent"
	pkgPdpLocal "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent/local"
	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var config = func() pkgAgentsCore.AgentConfig {
	agentType := pkgCore.GetEnv(pkgPdp.EnvKeyAutenticamiAgentType, pkgPdp.AutenticamiPDPAgentTypeLocal)
	if strings.ToUpper(agentType) == "PDP-LOCAL" {
		return pkgPdpLocal.NewLocalConfig()
	}
	log.Fatalf("%s: %s is an invalid agent type", pkgPdp.EnvKeyAutenticamiAgentType, agentType)
	panic(1)
}()

func init() {
	if config.IsLocalEnv() {
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
	if isLocalAgent {
		pdpServer.Service = pkgPdpLocal.NewPDPLocalService(config.(pkgPdpLocal.LocalConfig))
	} else {
		log.Fatal("pdp-remote is not implemented yet")
		os.Exit(1)
	}
	err = pdpServer.Service.Setup()
	if err != nil {
		log.Fatalf("pdpservice setup has failed: %v", err)
		os.Exit(1)
	}
	cmdPdpApiV1.RegisterPDPServiceServer(s, pdpServer)
	if config.IsLocalEnv() {
		reflection.Register(s)
		log.Info("grpc server registered the reflection service")
	}
	if err := s.Serve(lis); err != nil {
		log.Fatalf("grpc server failed: %v", err)
		os.Exit(1)
	}
}
