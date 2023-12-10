// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/autenticami/autenticami-authz/pkg/extensions"
	"github.com/google/uuid"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type PolicyStatementWrapper struct {
	ID                  uuid.UUID
	Statement           policies.PolicyStatement
	StatmentStringified string
	StatmentHashed      string
}

type PermissionsState struct {
	forbid map[string]PolicyStatementWrapper
	permit map[string]PolicyStatementWrapper
}

func newPermissionsState() *PermissionsState {
	return &PermissionsState{
		forbid: map[string]PolicyStatementWrapper{},
		permit: map[string]PolicyStatementWrapper{},
	}
}

func createPolicyStatementWrapper(policyStatement *policies.PolicyStatement) (*PolicyStatementWrapper, error) {
	if policyStatement == nil {
		return nil, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	policyStatementString, err := extensions.Stringify(policyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(policyStatementString))
	bs := h.Sum(nil)
	policyStatementHash := fmt.Sprintf("%x", bs)
	return &PolicyStatementWrapper{
		ID:                  uuid.New(),
		Statement:           *policyStatement,
		StatmentStringified: policyStatementString,
		StatmentHashed:      policyStatementHash,
	}, nil
}

func createPolicyStatementWrappers(wrappers map[string]PolicyStatementWrapper, policyStatements []policies.PolicyStatement) error {
	for _, policyStatement := range policyStatements {
		wrapper, err := createPolicyStatementWrapper(&policyStatement)
		if err != nil {
			return err
		}
		_, exists := wrappers[wrapper.StatmentHashed]
		if  exists {
			continue
		}
		wrappers[wrapper.StatmentHashed] = *wrapper
	}
	return nil
}

func fobidACLPolicyStatements(b *PermissionsState, policyStatements []policies.PolicyStatement) error {
	err := createPolicyStatementWrappers(b.forbid, policyStatements)
	if err != nil {
		return err
	}
	return nil
}

func permitACLPolicyStatements(b *PermissionsState, policyStatements []policies.PolicyStatement) error {
	err := createPolicyStatementWrappers(b.permit, policyStatements)
	if err != nil {
		return err
	}
	return nil
}

func clonePolicyStatementWrapper(policyStatements map[string]PolicyStatementWrapper) map[string]PolicyStatementWrapper {
	output := map[string]PolicyStatementWrapper{}
	for key, psw := range policyStatements {
		wrapper := PolicyStatementWrapper{}
		wrapper.ID = psw.ID
		wrapper.Statement = psw.Statement
		wrapper.StatmentStringified = psw.StatmentStringified
		wrapper.StatmentHashed = psw.StatmentHashed
		wrapper.Statement = psw.Statement
		output[key] = wrapper
	}
	return output
}

func clonePermissionsState(b *PermissionsState) *PermissionsState {
	permState := &PermissionsState{
		forbid: clonePolicyStatementWrapper(b.forbid),
		permit: clonePolicyStatementWrapper(b.permit),
	}
	return permState
}

func convertMapOfPolicyStatementWrapper(source map[string]PolicyStatementWrapper) []PolicyStatementWrapper {
	if source == nil {
		return []PolicyStatementWrapper{}
	}
	keys := make([]string, 0, len(source))
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]PolicyStatementWrapper, len(source))
	for i, key := range keys {
		items[i] = source[key]
	}
	return items
}

func (b *PermissionsState) GetForbidItems() []PolicyStatementWrapper {
	wrappers := clonePolicyStatementWrapper(b.forbid)
	return convertMapOfPolicyStatementWrapper(wrappers)
}

func (b *PermissionsState) GetPermitItems() []PolicyStatementWrapper {
	wrappers := clonePolicyStatementWrapper(b.permit)
	return convertMapOfPolicyStatementWrapper(wrappers)
}
