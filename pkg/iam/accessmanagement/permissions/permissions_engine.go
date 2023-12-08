// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/policies/

type PermissionsEngine struct {
	loader *permissionsLoader
}

func NewPermissionsEngine() *PermissionsEngine {
	loader := newPermissionsLoader()
	return &PermissionsEngine{
		loader: loader,
	}
}

func (d *PermissionsEngine) RegisterPolicy(bData []byte) (bool, error) {
	return d.loader.registerPolicy(bData)
}

func (d *PermissionsEngine) BuildPermissions() (*PermissionsState, error) {
	return d.loader.buildPermissionsState()
}
