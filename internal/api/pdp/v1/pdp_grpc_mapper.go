// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

func mapToACLPolicyStatement(aclPolicyStatement *policies.ACLPolicyStatement) (*ACLPolicyStatement, error) {
	result := &ACLPolicyStatement{
		Name:      string(aclPolicyStatement.Name),
		Actions:   make([]string, len(aclPolicyStatement.Actions)),
		Resources: make([]string, len(aclPolicyStatement.Resources)),
	}
	for i, action := range aclPolicyStatement.Actions {
		result.Actions[i] = string(action)
	}
	for i, resource := range aclPolicyStatement.Resources {
		result.Resources[i] = string(resource)
	}
	return result, nil
}

func mapToACLPolicyStatementWrapper(aclPolicyStatementWrapper *permissions.ACLPolicyStatementWrapper) (*ACLPolicyStatementWrapper, error) {
	aclPolicyStatement, err := mapToACLPolicyStatement(&aclPolicyStatementWrapper.Statement)
	if err != nil {
		return nil, err
	}
	result := &ACLPolicyStatementWrapper{
		Statement:      aclPolicyStatement,
		StatmentHashed: aclPolicyStatementWrapper.StatmentHashed,
	}
	return result, nil
}

func mapToPermissionsStateResponse(identityUUR string, permState *permissions.PermissionsState) (*PermissionsStateResponse, error) {
	var err error
	var forbidList []permissions.ACLPolicyStatementWrapper
	forbidList, err = permState.GetACLForbidItems()
	if err != nil {
		return nil, err
	}
	var permitList []permissions.ACLPolicyStatementWrapper
	permitList, err = permState.GetACLPermitItems()
	if err != nil {
		return nil, err
	}
	result := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: identityUUR,
		},
		PermissionsState: &PermissionsState{
			Permissions: &ACLPermissions{
				Forbid: make([]*ACLPolicyStatementWrapper, len(forbidList)),
				Permit: make([]*ACLPolicyStatementWrapper, len(permitList)),
			},
		},
	}
	for i, wrapper := range forbidList {
		aclPolicyStatementWrapper, err := mapToACLPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Forbid[i] = aclPolicyStatementWrapper
	}
	for i, wrapper := range permitList {
		aclPolicyStatementWrapper, err := mapToACLPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Permit[i] = aclPolicyStatementWrapper
	}
	return result, nil
}
