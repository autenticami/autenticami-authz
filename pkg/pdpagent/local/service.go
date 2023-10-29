// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import(
	pkgiAM "github.com/autenticami/autenticami-authz/pkg/internal/iam/accessmanagement"
)

type PDPLocalService struct {
	config LocalConfig
}

func (s PDPLocalService) Setup() {
}

func (s PDPLocalService) GetPermissionsState(identityUUR string) *pkgiAM.PermissionsState {
	return nil
}

func NewPDPLocalService(config LocalConfig) PDPLocalService {
	service := PDPLocalService {
		config: config,
	}
	return service
}
