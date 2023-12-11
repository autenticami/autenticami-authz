// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/policies/

type PermissionsEngine struct {
	loader *permissionsLoader
}

type PermissionsEngineOptions struct {
	enableVirtualState *bool
}

type PermissionsEngineOption func(permEngineSetting *PermissionsEngineOptions) error

func WithPermissionsEngineVirtualState(enableVirtualState bool) PermissionsEngineOption {
	return func(options *PermissionsEngineOptions) error {
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

func (d *PermissionsEngine) BuildPermissions(options ...PermissionsEngineOption) (*PermissionsState, error) {
	b := true
	var permEngineSettings = PermissionsEngineOptions{
		enableVirtualState: &b,
	}
	for _, option := range options {
		err := option(&permEngineSettings)
		if err != nil {
			return nil, err
		}
	}
	return d.loader.buildPermissionsState(*permEngineSettings.enableVirtualState)
}
