// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"crypto/sha256"
	"fmt"

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
	// sanitizedStatement           *PolicyStatement
	// sanitizedStatmentStringified string
	// sanitizedStatmentHashed      string
}

type PermissionsState struct {
	// duplicates map[uuid.UUID]uuid.UUID
	forbid []*PolicyStatementWrapper
	permit []*PolicyStatementWrapper
}

func newPermissionsState() *PermissionsState {
	return &PermissionsState{
		// duplicates: map[uuid.UUID]uuid.UUID{},
		forbid: make([]*PolicyStatementWrapper, 0),
		permit: make([]*PolicyStatementWrapper, 0),
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

func createPolicyStatementWrappers(policyStatements []*policies.PolicyStatement) ([]*PolicyStatementWrapper, error) {
	wrappers := make([]*PolicyStatementWrapper, len(policyStatements))
	for i, policyStatement := range policyStatements {
		wrapper, err := createPolicyStatementWrapper(policyStatement)
		if err != nil {
			return nil, err
		}
		wrappers[i] = wrapper
	}
	return wrappers, nil
}

func (b *PermissionsState) fobidACLPolicyStatements(policyStatements []*policies.PolicyStatement) error {
	wrappers, err := createPolicyStatementWrappers(policyStatements)
	if err != nil {
		return err
	}
	b.forbid = append(b.forbid, wrappers...)
	return nil
}

func (b *PermissionsState) permitACLPolicyStatements(policyStatements []*policies.PolicyStatement) error {
	wrappers, err := createPolicyStatementWrappers(policyStatements)
	if err != nil {
		return err
	}
	b.permit = append(b.permit, wrappers...)
	return nil
}

func (b *PermissionsState) GetForbidList() []*PolicyStatementWrapper {
	return b.clonePolicyStatementWrapper(b.forbid)
}

func (b *PermissionsState) GetPermitList() []*PolicyStatementWrapper {
	return b.clonePolicyStatementWrapper(b.permit)
}

func (b *PermissionsState) clonePolicyStatementWrapper(policyStatements []*PolicyStatementWrapper) []*PolicyStatementWrapper {
	output := make([]*PolicyStatementWrapper, len(policyStatements))
	for i, psw := range policyStatements {
		wrapper := &PolicyStatementWrapper{}
		wrapper.ID = psw.ID
		wrapper.Statement = psw.Statement
		wrapper.StatmentStringified = psw.StatmentStringified
		wrapper.StatmentHashed = psw.StatmentHashed
		wrapper.Statement = psw.Statement
		output[i] = wrapper
	}
	return output
}

func (b *PermissionsState) Clone() *PermissionsState {
	permState := &PermissionsState{
		forbid: b.clonePolicyStatementWrapper(b.forbid),
		permit: b.clonePolicyStatementWrapper(b.permit),
	}
	return permState
}
