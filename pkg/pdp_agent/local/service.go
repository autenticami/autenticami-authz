// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

type LocalService struct {
	config LocalConfig
}

func (c LocalService) IsLocal() LocalConfig {
	return c.config
}
