// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type PDPService interface {
	Setup() error
	GetPermissionsState(identityUUR policies.UURString) (*permissions.PermissionsState, error)
}
