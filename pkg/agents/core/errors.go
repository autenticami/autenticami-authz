// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"

	pkgiCore "github.com/autenticami/autenticami-authz/pkg/internal/core"
)

var (
	// ErrAgentLocalInvalidAppData is returned wether the appdata is invalid.
	ErrAgentLocalInvalidAppData = errors.Join(errors.New("agent: application data folder is invalid"), pkgiCore.ErrCodeGeneric)
	// ErrAgentLocalInvalidPort is returned wether the port is invalid.
	ErrAgentLocalInvalidPort = errors.Join(errors.New("agent: application port is invalid"), pkgiCore.ErrCodeGeneric)
)
