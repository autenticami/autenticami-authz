// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"sort"

	"github.com/autenticami/autenticami-authz/pkg/extensions/text"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type ACPolicyStatementWrapper struct {
	ID                  uuid.UUID
	Statement           policies.ACPolicyStatement
	StatmentStringified string
	StatmentHashed      string
}

func createACPolicyStatementWrapper(acPolicyStatement *policies.ACPolicyStatement) (*ACPolicyStatementWrapper, error) {
	if acPolicyStatement == nil {
		return nil, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	acPolicyStatementString, err := text.Stringify(acPolicyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	acPolicyStatementHash := text.CreateStringHash(acPolicyStatementString)
	return &ACPolicyStatementWrapper{
		ID:                  uuid.New(),
		Statement:           *acPolicyStatement,
		StatmentStringified: acPolicyStatementString,
		StatmentHashed:      acPolicyStatementHash,
	}, nil
}

func createACPolicyStatementWrappers(wrappers map[string]ACPolicyStatementWrapper, acPolicyStatements []policies.ACPolicyStatement) error {
	if acPolicyStatements == nil {
		return authzAMErrors.ErrAccessManagementInvalidDataType
	}
	for _, acPolicyStatement := range acPolicyStatements {
		wrapper, err := createACPolicyStatementWrapper(&acPolicyStatement)
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

type ACPermissions struct {
	forbid map[string]ACPolicyStatementWrapper
	permit map[string]ACPolicyStatementWrapper
}

type PermissionsState struct {
	permissions ACPermissions
}

func newPermissionsState() *PermissionsState {
	return &PermissionsState{
		permissions: ACPermissions{
			forbid: map[string]ACPolicyStatementWrapper{},
			permit: map[string]ACPolicyStatementWrapper{},
		},
	}
}

func (b *PermissionsState) convertACPolicyStatementsMapToArray(source map[string]ACPolicyStatementWrapper) []ACPolicyStatementWrapper {
	if source == nil {
		return []ACPolicyStatementWrapper{}
	}
	keys := make([]string, 0)
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]ACPolicyStatementWrapper, len(source))
	for i, key := range keys {
		items[i] = source[key]
	}
	return items
}

func (b *PermissionsState) cloneACPolicyStatements(acPolicyStatements map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	dest := map[string]ACPolicyStatementWrapper{}
	err := copier.Copy(&dest, acPolicyStatements)
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

func (b *PermissionsState) GetACForbiddenPermissions() ([]ACPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACPolicyStatements(b.permissions.forbid)
	if err != nil {
		return nil, err
	}
	return b.convertACPolicyStatementsMapToArray(wrappers), nil
}

func (b *PermissionsState) GetACPermittedPermissions() ([]ACPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACPolicyStatements(b.permissions.permit)
	if err != nil {
		return nil, err
	}
	return b.convertACPolicyStatementsMapToArray(wrappers), nil
}
