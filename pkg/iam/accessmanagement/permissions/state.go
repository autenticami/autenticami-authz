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

type ACLPolicyStatementWrapper struct {
	ID                  uuid.UUID
	Statement           policies.ACLPolicyStatement
	StatmentStringified string
	StatmentHashed      string
}

func createACLPolicyStatementWrapper(aclPolicyStatement *policies.ACLPolicyStatement) (*ACLPolicyStatementWrapper, error) {
	if aclPolicyStatement == nil {
		return nil, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	aclPolicyStatementString, err := text.Stringify(aclPolicyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(aclPolicyStatementString))
	bs := h.Sum(nil)
	aclPolicyStatementHash := fmt.Sprintf("%x", bs)
	return &ACLPolicyStatementWrapper{
		ID:                  uuid.New(),
		Statement:           *aclPolicyStatement,
		StatmentStringified: aclPolicyStatementString,
		StatmentHashed:      aclPolicyStatementHash,
	}, nil
}

func createACLPolicyStatementWrappers(wrappers map[string]ACLPolicyStatementWrapper, aclPolicyStatements []policies.ACLPolicyStatement) error {
	for _, aclPolicyStatement := range aclPolicyStatements {
		wrapper, err := createACLPolicyStatementWrapper(&aclPolicyStatement)
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
	forbid map[string]ACLPolicyStatementWrapper
	permit map[string]ACLPolicyStatementWrapper
}

func newPermissionsState() *PermissionsState {
	return &PermissionsState{
		forbid: map[string]ACLPolicyStatementWrapper{},
		permit: map[string]ACLPolicyStatementWrapper{},
	}
}

func (b *PermissionsState) convertACLPolicyStatementsMapToArray(source map[string]ACLPolicyStatementWrapper) []ACLPolicyStatementWrapper {
	if source == nil {
		return []ACLPolicyStatementWrapper{}
	}
	keys := make([]string, 0)
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]ACLPolicyStatementWrapper, len(source))
	for i, key := range keys {
		items[i] = source[key]
	}
	return items
}

func (b *PermissionsState) cloneACLPolicyStatements(aclPolicyStatements map[string]ACLPolicyStatementWrapper) (map[string]ACLPolicyStatementWrapper, error) {
	dest := map[string]ACLPolicyStatementWrapper{}
	err := copier.Copy(&dest, aclPolicyStatements)
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

func (b *PermissionsState) GetACLForbidItems() ([]ACLPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACLPolicyStatements(b.forbid)
	if err != nil {
		return nil, err
	}
	return b.convertACLPolicyStatementsMapToArray(wrappers), nil
}

func (b *PermissionsState) GetACLPermitItems() ([]ACLPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACLPolicyStatements(b.permit)
	if err != nil {
		return nil, err
	}
	return b.convertACLPolicyStatementsMapToArray(wrappers), nil
}
