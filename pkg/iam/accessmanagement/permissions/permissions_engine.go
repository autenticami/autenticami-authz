// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/policies/

type PermissionsEngine struct {
	loader *permissionsLoader
}

type PermissionsEngineSettings struct {
	enableVirtualState *bool
}

type PermissionsEngineSetting func(permEngineSetting *PermissionsEngineSettings) error

func WithPermissionsEngineVirtualState(enableVirtualState bool) PermissionsEngineSetting {
	return func(options *PermissionsEngineSettings) error {
		options.enableVirtualState = &enableVirtualState
		return nil
	}
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

func (d *PermissionsEngine) BuildPermissions(settings ...PermissionsEngineSetting) (*PermissionsState, error) {
	b := true
	var permEngineSettings = PermissionsEngineSettings{
		enableVirtualState: &b,
	}
	for _, setting := range settings {
		err := setting(&permEngineSettings)
		if err != nil {
			return nil, err
		}
	}
	return d.loader.buildPermissionsState(*permEngineSettings.enableVirtualState)
}
