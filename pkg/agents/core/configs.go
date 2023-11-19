// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"
)

type AgentConfig struct {
	isLocal   bool
	agentType string
	appData   string
	appPort   string
}

func (c *AgentConfig) IsLocalEnv() bool {
	return c.isLocal
}

func (c *AgentConfig) GetAgentType() string {
	return c.agentType
}

func (c *AgentConfig) GetAgentPort() string {
	return c.appPort
}

func (c *AgentConfig) GetAgentAppData() string {
	return c.appData
}

func NewAgentConfig(agentType string) (*AgentConfig, error) {
	localConfig := &AgentConfig{
		isLocal:   GetEnv(EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: agentType,
		appData:   GetEnv(EnvKeyAutenticamiAgentAppData, "."),
		appPort:   GetEnv(EnvKeyAutenticamiAgentPort, "9090"),
	}
	if !pkgCore.IsValidPath(localConfig.appData) {
		return nil, ErrAgentLocalInvalidAppData
	}
	if !pkgCore.IsValidPort(localConfig.appPort) {
		return nil, ErrAgentLocalInvalidPort
	}
	return localConfig, nil
}
