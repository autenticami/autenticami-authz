// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"os"

	"github.com/autenticami/autenticami-authz/internal/agents/errors"
	"github.com/autenticami/autenticami-authz/internal/agents/extensions/environments"
	"github.com/autenticami/autenticami-authz/internal/agents/extensions/validations"
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
		isLocal:   environments.GetEnv(EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		agentType: environments.GetEnv(EnvKeyAutenticamiAgentType, agentType),
		appData:   os.ExpandEnv(environments.GetEnv(EnvKeyAutenticamiAgentAppData, "./")),
		appPort:   environments.GetEnv(EnvKeyAutenticamiAgentPort, "9090"),
	}
	if !validations.IsValidPath(localConfig.appData) {
		return nil, errors.ErrAgentInvalidAppData
	}
	if !validations.IsValidPort(localConfig.appPort) {
		return nil, errors.ErrAgentInvalidPort
	}
	if len(localConfig.agentType) == 0 {
		return nil, errors.ErrAgentInvalidType
	}
	return localConfig, nil
}
