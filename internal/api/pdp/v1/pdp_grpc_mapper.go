// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

func mapToACPolicyStatement(acPolicyStatement *policies.ACPolicyStatement) (*ACPolicyStatement, error) {
	result := &ACPolicyStatement{
		Name:      string(acPolicyStatement.Name),
		Actions:   make([]string, len(acPolicyStatement.Actions)),
		Resources: make([]string, len(acPolicyStatement.Resources)),
		Condition: acPolicyStatement.Condition,
	}
	for i, action := range acPolicyStatement.Actions {
		result.Actions[i] = string(action)
	}
	for i, resource := range acPolicyStatement.Resources {
		result.Resources[i] = string(resource)
	}
	return result, nil
}

func mapToACPolicyStatementWrapper(acPolicyStatementWrapper *permissions.ACPolicyStatementWrapper) (*ACPolicyStatementWrapper, error) {
	acPolicyStatement, err := mapToACPolicyStatement(&acPolicyStatementWrapper.Statement)
	if err != nil {
		return nil, err
	}
	result := &ACPolicyStatementWrapper{
		Statement:      acPolicyStatement,
		StatmentHashed: acPolicyStatementWrapper.StatmentHashed,
	}
	return result, nil
}

func mapToPermissionsStateResponse(identityUUR string, permState *permissions.PermissionsState) (*PermissionsStateResponse, error) {
	var err error
	var forbidList []permissions.ACPolicyStatementWrapper
	forbidList, err = permState.GetACForbiddenPermissions()
	if err != nil {
		return nil, err
	}
	var permitList []permissions.ACPolicyStatementWrapper
	permitList, err = permState.GetACPermittedPermissions()
	if err != nil {
		return nil, err
	}
	result := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: identityUUR,
		},
		PermissionsState: &PermissionsState{
			Permissions: &ACPermissions{
				Forbid: make([]*ACPolicyStatementWrapper, len(forbidList)),
				Permit: make([]*ACPolicyStatementWrapper, len(permitList)),
			},
		},
	}
	for i, wrapper := range forbidList {
		acPolicyStatementWrapper, err := mapToACPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Forbid[i] = acPolicyStatementWrapper
	}
	for i, wrapper := range permitList {
		acPolicyStatementWrapper, err := mapToACPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Permit[i] = acPolicyStatementWrapper
	}
	return result, nil
}
