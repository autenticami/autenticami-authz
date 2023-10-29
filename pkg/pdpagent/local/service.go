// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

type PDPLocalService struct {
	config LocalConfig
}

func (s PDPLocalService) Setup() {
}

func NewPDPLocalService(config LocalConfig) PDPLocalService {
	service := PDPLocalService {
		config: config,
	}
	return service
}
