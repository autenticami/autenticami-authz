// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package pdpagent

import (
	pkgAgentsCore "github.com/autenticami/autenticami-authz/pkg/agents/core"
)

type PDPAgentConfig struct {
	pkgAgentsCore.AgentConfig
}

func NewPDPAgentConfig() (*PDPAgentConfig, error) {
	config, err := pkgAgentsCore.NewAgentConfig(AutenticamiPDPAgentTypeLocal)
	if err != nil {
		return nil, err
	}
	localConfig := &PDPAgentConfig{
		*config,
	}
	return localConfig, nil
}
