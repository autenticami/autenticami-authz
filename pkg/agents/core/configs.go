// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import(
	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"
)

type AgentConfig interface {
	pkgCore.Config
	GetAgentType() string
}
