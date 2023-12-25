// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
)

type extendedPermissionsState struct {
	*PermissionsState
}

func newExtendedPermissionsState(permsState *PermissionsState) *extendedPermissionsState {
	return &extendedPermissionsState{permsState}
}

func (b *extendedPermissionsState) fobidACPolicyStatements(acPolicyStatements []policies.ACPolicyStatement) error {
	err := createACPolicyStatementWrappers(b.permissions.forbid, acPolicyStatements)
	if err != nil {
		return err
	}
	return nil
}

func (b *extendedPermissionsState) permitACPolicyStatements(acPolicyStatements []policies.ACPolicyStatement) error {
	err := createACPolicyStatementWrappers(b.permissions.permit, acPolicyStatements)
	if err != nil {
		return err
	}
	return nil
}
