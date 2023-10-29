// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"

	pkgiCore "github.com/autenticami/autenticami-authz/pkg/internal/core"
)

var (
	// ErrPDPAgentLocalInvalidAppData is returned wether the appdata is invalid.
	ErrPDPAgentLocalInvalidAppData = errors.Join(errors.New("pdpagent: application data folder is invalid"), pkgiCore.ErrCodeGeneric)
)
