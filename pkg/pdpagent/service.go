// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package pdpagent

import(
	pkgiAM "github.com/autenticami/autenticami-authz/pkg/internal/iam/accessmanagement"
)

type PDPService interface {
	Setup()
	GetPermissionsState(identityUUR string) *pkgiAM.PermissionsState
}
