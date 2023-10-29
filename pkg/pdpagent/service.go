// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package pdpagent

import(
	pkgAM "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPService interface {
	Setup()
	GetPermissionsState(identityUUR pkgAM.UURString) *pkgAM.PermissionsState
}
