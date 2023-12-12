// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type extendedPermissionsState struct {
    *PermissionsState
}

func newExtendedPermissionsState(permsState *PermissionsState) *extendedPermissionsState {
	return &extendedPermissionsState{permsState}
}

func (b *extendedPermissionsState) fobidACLPolicyStatements(policyStatements []policies.PolicyStatement) error {
	err := createPolicyStatementWrappers(b.forbid, policyStatements)
	if err != nil {
		return err
	}
	return nil
}

func (b *extendedPermissionsState) permitACLPolicyStatements(policyStatements []policies.PolicyStatement) error {
	err := createPolicyStatementWrappers(b.permit, policyStatements)
	if err != nil {
		return err
	}
	return nil
}
