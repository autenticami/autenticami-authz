// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

var (
	// ErrPDPAgentGeneric is returned wether there is a generic error.
	ErrPDPAgentGeneric = errors.Join(errors.New("pdpagent: generic error"), authzErrors.ErrGeneric)
)
