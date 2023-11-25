// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"github.com/autenticami/autenticami-authz/internal/agents/configs"
)

type PDPAgentConfig struct {
	configs.AgentConfig
}

func NewPDPAgentConfig() (*PDPAgentConfig, error) {
	config, err := configs.NewAgentConfig(AutenticamiPDPAgentTypeLocal)
	if err != nil {
		return nil, err
	}
	localConfig := &PDPAgentConfig{
		*config,
	}
	return localConfig, nil
}
