// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

var (
	// ErrAgentInvalidAppData is returned wether the appdata is invalid.
	ErrAgentInvalidAppData = errors.Join(errors.New("agent: application data folder is invalid"), authzErrors.ErrGeneric)
	// ErrAgentInvalidPort is returned wether the port is invalid.
	ErrAgentInvalidPort = errors.Join(errors.New("agent: application port is invalid"), authzErrors.ErrGeneric)
	// ErrAgentInvalidType is returned wether the agent type is invalid.
	ErrAgentInvalidType = errors.Join(errors.New("agent: application type is invalid"), authzErrors.ErrGeneric)
)
