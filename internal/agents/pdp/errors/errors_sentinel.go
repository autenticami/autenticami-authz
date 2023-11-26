// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

var (
	// ErrPDPAgentLocalInvalidAppData is returned wether the appdata is invalid.
	ErrPDPAgentLocalInvalidAppData = errors.Join(errors.New("pdpagent: application data folder is invalid"), authzErrors.ErrGeneric)
	// ErrPDPAgentLocalInvalidPort is returned wether the port is invalid.
	ErrPDPAgentLocalInvalidPort = errors.Join(errors.New("pdpagent: application port is invalid"), authzErrors.ErrGeneric)
)
