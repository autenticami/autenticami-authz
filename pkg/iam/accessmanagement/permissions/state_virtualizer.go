// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"strings"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

type permissionsStateVirtualizer struct {
	permissionState *PermissionsState
}

func newPermissionsStateVirtualizer(permsState *PermissionsState) *permissionsStateVirtualizer {
	return &permissionsStateVirtualizer{
		permissionState: permsState,
	}
}

func (v *permissionsStateVirtualizer) virualizePolicyStatementsWithASingleResource(statements []*policies.PolicyStatement) ([]*policies.PolicyStatement, error) {
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
		//policyStatement := cacheItem
		cleanedStatements[counter] = cacheItem
		counter++
	}
	return cleanedStatements, nil
}

func (v *permissionsStateVirtualizer) virualizePolicyStatements(wrappers map[string]PolicyStatementWrapper) ([]*policies.PolicyStatement, error) {
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
				dest.Name = policies.PolicyLabelString((strings.Replace(uuid.NewString(), "-", "", -1)))
				if len(dest.Resources) > 1 {
					dest.Resources = []policies.UURString{resource}
				}
				statements = append(statements, &dest)
			}
		}
	}
	return v.virualizePolicyStatementsWithASingleResource(statements)
}

func (v *permissionsStateVirtualizer) virtualize() (*PermissionsState, error) {
	newPermState := newPermissionsState()
	var err error
	var fobidItems []*policies.PolicyStatement
	fobidItems, err = v.virualizePolicyStatements(v.permissionState.forbid)
	if err != nil {
		return nil, err
	}
	extPermsState := newExtendedPermissionsState(newPermState)
	for _, fobidItem := range fobidItems {
		err := extPermsState.fobidACLPolicyStatements([]policies.PolicyStatement{*fobidItem})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []*policies.PolicyStatement
	permitItems, err = v.virualizePolicyStatements(v.permissionState.permit)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := extPermsState.permitACLPolicyStatements([]policies.PolicyStatement{*permitItem})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
