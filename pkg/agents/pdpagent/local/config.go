// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	pkgAgent "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent"
	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"
)

type LocalConfig struct {
	isLocal   bool
	agentType string
	appData   string
}

func (c LocalConfig) GetGoEnv() bool {
	return c.isLocal
}

func (c LocalConfig) GetAgentType() string {
	return c.agentType
}

func NewLocalConfig() LocalConfig {
	localConfig := LocalConfig{
		isLocal:   pkgCore.GetEnv(pkgAgent.EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: pkgAgent.AutenticamiPDPAgentTypeLocal,
		appData:   pkgCore.GetEnv(pkgAgent.EnvKeyAutenticamiAgentAppData, "."),
	}
	return localConfig
}
