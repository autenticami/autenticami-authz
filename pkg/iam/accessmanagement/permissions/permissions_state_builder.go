// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

type PermissionsStateBuilder struct {
	permissionsState *PermissionsState
}

func newPermissionsStateBuilder() *PermissionsStateBuilder {
	return &PermissionsStateBuilder{}
}

func (b *PermissionsStateBuilder) setInstance(permState *PermissionsState) {
	b.permissionsState = permState
}

func (b *PermissionsStateBuilder) build(enableVirtualState bool) (*PermissionsState, error) {
	if enableVirtualState {
		return newPermissionsVirtualState(b.permissionsState)
	}
	return b.permissionsState.clone()
}
