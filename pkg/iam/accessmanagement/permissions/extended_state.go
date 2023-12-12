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

func (b *extendedPermissionsState) fobidACLPolicyStatements(aclPolicyStatements []policies.ACLPolicyStatement) error {
	err := createACLPolicyStatementWrappers(b.forbid, aclPolicyStatements)
	if err != nil {
		return err
	}
	return nil
}

func (b *extendedPermissionsState) permitACLPolicyStatements(aclPolicyStatements []policies.ACLPolicyStatement) error {
	err := createACLPolicyStatementWrappers(b.permit, aclPolicyStatements)
	if err != nil {
		return err
	}
	return nil
}
