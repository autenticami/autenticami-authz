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

func (b *PermissionsState) GetForbidItems() ([]PolicyStatementWrapper, error) {
	wrappers, err := clonePolicyStatementWrapper(b.forbid)
	if err != nil {
		return nil, err
	}
	return convertMapOfPolicyStatementWrapper(wrappers), nil
}

func (b *PermissionsState) GetPermitItems() ([]PolicyStatementWrapper, error) {
	wrappers, err := clonePolicyStatementWrapper(b.permit)
	if err != nil {
		return nil, err
	}
	return convertMapOfPolicyStatementWrapper(wrappers), nil
}

// Permissions State functions

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

func clonePolicyStatementWrapper(policyStatements map[string]PolicyStatementWrapper) (map[string]PolicyStatementWrapper, error) {
	dest := map[string]PolicyStatementWrapper{}
	err := copier.Copy(&dest, policyStatements)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

func clonePermissionsState(b *PermissionsState) (*PermissionsState, error) {
	dest := PermissionsState{}
	err := copier.Copy(&dest, b)
	if err != nil {
		return nil, err
	}
	return &dest, nil
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

// Permissions Virtual State functions

func virualizePolicyStatementsWithASingleResource(statements []*policies.PolicyStatement) ([]*policies.PolicyStatement, error) {
	cache := map[string]*policies.PolicyStatement{}
	for _, statement := range statements {
		policyStatement := *statement
		resource := string(policyStatement.Resources[0])
		val, ok := cache[resource]
		if !ok {
			cache[resource] = &policyStatement
			continue
		}
		val.Actions = append(val.Actions, policyStatement.Actions...)
	}
	cleanedStatements := make([]*policies.PolicyStatement, len(cache))
	counter := 0
	for _, cacheItem := range cache {
		policyStatement := cacheItem
		cleanedStatements[counter] = policyStatement
		counter++
	}
	return cleanedStatements, nil
}

func virualizePolicyStatementsWrappers(wrappers map[string]PolicyStatementWrapper) ([]*policies.PolicyStatement, error) {
	statements := make([]*policies.PolicyStatement, 0)
	for _, wrapper := range wrappers {
		if len(wrapper.Statement.Resources) == 0 {
			continue
		} else {
			for _, resource := range wrapper.Statement.Resources {
				dest := policies.PolicyStatement{}
				err := copier.Copy(&dest, &wrapper.Statement)
				if err != nil {
					return nil, err
				}
				dest.Resources = []policies.UURString{resource}
				statements = append(statements, &dest)
			}
		}
	}
	return virualizePolicyStatementsWithASingleResource(statements)
}

func newPermissionsVirtualState(permState *PermissionsState) (*PermissionsState, error) {
	newPermState := newPermissionsState()
	var err error
	var fobidItems []*policies.PolicyStatement
	fobidItems, err = virualizePolicyStatementsWrappers(permState.forbid)
	if err != nil {
		return nil, err
	}
	for _, fobidItem := range fobidItems {
		err := fobidACLPolicyStatements(newPermState, []policies.PolicyStatement{*fobidItem})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []*policies.PolicyStatement
	permitItems, err = virualizePolicyStatementsWrappers(permState.permit)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := permitACLPolicyStatements(newPermState, []policies.PolicyStatement{*permitItem})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
