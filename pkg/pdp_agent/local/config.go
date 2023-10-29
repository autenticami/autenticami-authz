// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	pkg_core "github.com/autenticami/autenticami-authz/pkg/core"
	pkg_agent "github.com/autenticami/autenticami-authz/pkg/pdp_agent"
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
		isLocal: pkg_core.GetEnv(pkg_agent.EnvKeyAutenticamiEnvironment, "LOCAL") == "LOCAL",
		appData: pkg_core.GetEnv(pkg_agent.EnvKeyAutenticamiAgentAppData, "."),
	}
	return localConfig
}
