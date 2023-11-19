// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	pkgAgent "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent"
	pkgAgentsCore "github.com/autenticami/autenticami-authz/pkg/agents/core"
)

type LocalConfig struct {
	isLocal   bool
	agentType string
	appData   string
	appPort   string
}

func (c LocalConfig) IsLocalEnv() bool {
	return c.isLocal
}

func (c LocalConfig) GetAgentType() string {
	return c.agentType
}

func (c LocalConfig) GetAgentPort() string {
	return c.appPort
}

func NewLocalConfig() LocalConfig {
	localConfig := LocalConfig{
		isLocal:   pkgAgentsCore.GetEnv(pkgAgent.EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: pkgAgent.AutenticamiPDPAgentTypeLocal,
		appData:   pkgAgentsCore.GetEnv(pkgAgent.EnvKeyAutenticamiAgentAppData, "."),
		appPort:   pkgAgentsCore.GetEnv(pkgAgent.EnvKeyAutenticamiAgentPort, "9090"),
	}
	return localConfig
}
