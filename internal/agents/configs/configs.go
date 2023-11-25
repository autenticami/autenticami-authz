// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"github.com/autenticami/autenticami-authz/internal/agents/errors"
	"github.com/autenticami/autenticami-authz/internal/agents/extensions"
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
		isLocal:   extensions.GetEnv(EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: agentType,
		appData:   extensions.GetEnv(EnvKeyAutenticamiAgentAppData, "."),
		appPort:   extensions.GetEnv(EnvKeyAutenticamiAgentPort, "9090"),
	}
	if !extensions.IsValidPath(localConfig.appData) {
		return nil, errors.ErrAgentLocalInvalidAppData
	}
	if !extensions.IsValidPort(localConfig.appPort) {
		return nil, errors.ErrAgentLocalInvalidPort
	}
	return localConfig, nil
}
