// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	am "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPService interface {
	Setup() error
	GetPermissionsState(identityUUR am.UURString) (*am.PermissionsState, error)
}
