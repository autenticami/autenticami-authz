package main

import (
	"context"
    "runtime/debug"
	"net"
	"os"
	"strings"
	"time"

	cmdPdpApiV1 "github.com/autenticami/autenticami-authz/cmd/pdpagent/api/v1"
	pkgAgentsCore "github.com/autenticami/autenticami-authz/pkg/agents/core"
	pkgPdp "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent"
	pkgPdpLocal "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent/local"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var config = func() pkgAgentsCore.AgentConfig {
	agentType := pkgAgentsCore.GetEnv(pkgPdp.EnvKeyAutenticamiAgentType, pkgPdp.AutenticamiPDPAgentTypeLocal)
	if strings.ToUpper(agentType) == pkgPdp.AutenticamiPDPAgentTypeLocal {
		return pkgPdpLocal.NewLocalConfig()
	}
	log.Fatalf("%s: %s is an invalid agent type", pkgPdp.EnvKeyAutenticamiAgentType, agentType)
	panic(1)
}()

func init() {
	if config.IsLocalEnv() {
		// log as ASCII instead of the default JSON formatter.
		log.SetFormatter(&log.TextFormatter{ForceColors: true, DisableColors: false, FullTimestamp: true})
		// output to stdout instead of the default stderr
		log.SetOutput(os.Stdout)
		// only log the info severity or above.
		log.SetLevel(log.InfoLevel)
	} else {
		// log as JSON instead of the default ASCII formatter.
		log.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
		// output to stdout instead of the default stderr
		log.SetOutput(os.Stdout)
		// only log the info severity or above.
		log.SetLevel(log.WarnLevel)
	}
}

// serverInterceptor is a unary interceptor that logs the duration of each request.
func serverInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("panic occurred: %v stacktrace:%s", err, debug.Stack())
		}
	}()
	start := time.Now()
	h, err := handler(ctx, req)
	if err != nil {
		log.Errorf("request - method:%s duration:%s error:%v", info.FullMethod, time.Since(start), err)
	} else {
		log.Infof("request - method:%s duration:%s", info.FullMethod, time.Since(start))
	}
	return h, err
}

// withServerUnaryInterceptor returns a grpc.ServerOption that adds a unary interceptor to the server.
func withServerUnaryInterceptor() grpc.ServerOption {
	return grpc.UnaryInterceptor(serverInterceptor)
}

func main() {
	isLocalAgent := config.GetAgentType() == pkgPdp.AutenticamiPDPAgentTypeLocal
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("tcp connection failed: %v", err)
		os.Exit(1)
	}
	log.Infof("listening at %v", lis.Addr())

	s := grpc.NewServer(
		withServerUnaryInterceptor(),
	)

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
	} else {
		log.Info("pdpservice setup succeded")
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
