// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	pCore "github.com/autenticami/autenticami-authz/pkg/internal/core"
	"github.com/autenticami/autenticami-authz/pkg/pdp_agent"
)

type LocalConfig struct {
	isLocal bool
	appData string
}

func (c LocalConfig) IsLocal() bool {
	return c.isLocal
}

func NewLocalConfig() LocalConfig {
	localConfig := LocalConfig{
		isLocal: pCore.GetEnv(pdp_agent.EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		appData: pCore.GetEnv(pdp_agent.EnvKeyAutenticamiAgentAppData, "."),
	}
	return localConfig
}
