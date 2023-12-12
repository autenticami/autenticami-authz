// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/autenticami/autenticami-authz/pkg/extensions/text"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type PolicyStatementWrapper struct {
	ID                  uuid.UUID
	Statement           policies.PolicyStatement
	StatmentStringified string
	StatmentHashed      string
}

func createPolicyStatementWrapper(policyStatement *policies.PolicyStatement) (*PolicyStatementWrapper, error) {
	if policyStatement == nil {
		return nil, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	policyStatementString, err := text.Stringify(policyStatement, []string{"Name"})
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
		if exists {
			continue
		}
		wrappers[wrapper.StatmentHashed] = *wrapper
	}
	return nil
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

func (b *PermissionsState) convertPolicyStatementsMapToArray(source map[string]PolicyStatementWrapper) []PolicyStatementWrapper {
	if source == nil {
		return []PolicyStatementWrapper{}
	}
	keys := make([]string, 0)
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

func (b *PermissionsState) clonePolicyStatements(policyStatements map[string]PolicyStatementWrapper) (map[string]PolicyStatementWrapper, error) {
	dest := map[string]PolicyStatementWrapper{}
	err := copier.Copy(&dest, policyStatements)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

func (b *PermissionsState) clone() (*PermissionsState, error) {
	dest := PermissionsState{}
	err := copier.Copy(&dest, b)
	if err != nil {
		return nil, err
	}
	return &dest, nil
}

func (b *PermissionsState) GetForbidItems() ([]PolicyStatementWrapper, error) {
	wrappers, err := b.clonePolicyStatements(b.forbid)
	if err != nil {
		return nil, err
	}
	return b.convertPolicyStatementsMapToArray(wrappers), nil
}

func (b *PermissionsState) GetPermitItems() ([]PolicyStatementWrapper, error) {
	wrappers, err := b.clonePolicyStatements(b.permit)
	if err != nil {
		return nil, err
	}
	return b.convertPolicyStatementsMapToArray(wrappers), nil
}
