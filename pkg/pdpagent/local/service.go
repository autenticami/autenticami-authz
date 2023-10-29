// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import(
	pkgAM "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPLocalService struct {
	config LocalConfig
}

func (s PDPLocalService) Setup() {
}

func (s PDPLocalService) GetPermissionsState(identityUUR pkgAM.UURString) *pkgAM.PermissionsState {
	return nil
}

func NewPDPLocalService(config LocalConfig) PDPLocalService {
	service := PDPLocalService {
		config: config,
	}
	return service
}
