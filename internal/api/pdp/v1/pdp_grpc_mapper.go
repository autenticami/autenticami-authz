// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

func mapToPolicyStatement(policyStatement *policies.PolicyStatement) (*PolicyStatement, error) {
	result := &PolicyStatement{
		Name:      string(policyStatement.Name),
		Actions:   make([]string, len(policyStatement.Actions)),
		Resources: make([]string, len(policyStatement.Resources)),
	}
	for i, action := range policyStatement.Actions {
		result.Actions[i] = string(action)
	}
	for i, resource := range policyStatement.Resources {
		result.Resources[i] = string(resource)
	}
	return result, nil
}

func mapToPolicyStatementWrapper(policyStatementWrapper *permissions.PolicyStatementWrapper) (*PolicyStatementWrapper, error) {
	policyStatement, err := mapToPolicyStatement(&policyStatementWrapper.Statement)
	if err != nil {
		return nil, err
	}
	result := &PolicyStatementWrapper{
		Statement:           policyStatement,
		StatmentHashed:      policyStatementWrapper.StatmentHashed,
	}
	return result, nil
}

func mapToPermissionsStateResponse(identityUUR string, permissionsState *permissions.PermissionsState) (*PermissionsStateResponse, error) {
	forbidList := permissionsState.GetForbidList()
	permitList := permissionsState.GetPermitList()
	result := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: identityUUR,
		},
		PermissionsState: &PermissionsState{
			Forbid: make([]*PolicyStatementWrapper, len(forbidList)),
			Permit: make([]*PolicyStatementWrapper, len(permitList)),
		},
	}
	for i, wrapper := range forbidList {
		policyStatementWrapper, err := mapToPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Forbid[i] = policyStatementWrapper
	}
	for i, wrapper := range permitList {
		policyStatementWrapper, err := mapToPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permit[i] = policyStatementWrapper
	}
	return result, nil
}
