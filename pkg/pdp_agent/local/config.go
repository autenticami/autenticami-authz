// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	pCore "github.com/autenticami/autenticami-authz/pkg/internal/core"
)

type LocalConfig struct {
	IsLocal bool
}

func NewLocalConfig() (LocalConfig) {
	localConfig := LocalConfig{
		IsLocal: pCore.GetEnv("IS_LOCAL", "LOCAL") == "LOCAL",
	}
	return localConfig
}