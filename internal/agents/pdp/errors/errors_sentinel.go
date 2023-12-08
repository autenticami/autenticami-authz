// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

// ErrPDPAgentGeneric is returned wether there is a generic error.
var ErrPDPAgentGeneric = errors.Join(errors.New("pdpagent: generic error"), authzErrors.ErrGeneric)
