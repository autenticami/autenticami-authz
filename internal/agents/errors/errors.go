// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	iErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

var (
	// ErrAgentLocalInvalidAppData is returned wether the appdata is invalid.
	ErrAgentLocalInvalidAppData = errors.Join(errors.New("agent: application data folder is invalid"), iErrors.ErrGeneric)
	// ErrAgentLocalInvalidPort is returned wether the port is invalid.
	ErrAgentLocalInvalidPort = errors.Join(errors.New("agent: application port is invalid"), iErrors.ErrGeneric)
)
