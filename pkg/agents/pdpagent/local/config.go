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
}

func (c LocalConfig) IsLocalEnv() bool {
	return c.isLocal
}

func (c LocalConfig) GetAgentType() string {
	return c.agentType
}

func NewLocalConfig() LocalConfig {
	localConfig := LocalConfig{
		isLocal:   pkgAgentsCore.GetEnv(pkgAgent.EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: pkgAgent.AutenticamiPDPAgentTypeLocal,
		appData:   pkgAgentsCore.GetEnv(pkgAgent.EnvKeyAutenticamiAgentAppData, "."),
	}
	return localConfig
}
