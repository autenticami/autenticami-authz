// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/permissions-policies/

type PermissionsEngine struct {
	loader *permissionsLoader
}

func NewPermissionsEngine() *PermissionsEngine {
	loader := newPermissionsLoader()
	return &PermissionsEngine {
		loader: loader,
	}
}

func (d *PermissionsEngine) BuildPermissions(bData []byte) (*PermissionsState, error) {
	_, err := d.loader.registerPolicy(bData)
	if err != nil {
		return nil, err
	}
	state, err := d.loader.buildPermissionsState()
	if err != nil {
		return nil, err
	}
	return &state, nil
}
