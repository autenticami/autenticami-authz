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
	syntaxVersion		policies.PolicyVersionString
	permissionState *PermissionsState
}

func newPermissionsStateVirtualizer(syntaxVersion policies.PolicyVersionString,permsState *PermissionsState) *permissionsStateVirtualizer {
	return &permissionsStateVirtualizer{
		syntaxVersion: syntaxVersion,
		permissionState: permsState,
	}
}

func (v *permissionsStateVirtualizer) virualizeACLPolicyStatementsWithASingleResource(aclPolicyStatements []*policies.ACLPolicyStatement) ([]*policies.ACLPolicyStatement, error) {
	cache := map[string]*policies.ACLPolicyStatement{}
	for _, aclPolicyStatement := range aclPolicyStatements {
		statement := *aclPolicyStatement
		policies.SanitizeACLPolicyStatement(v.syntaxVersion, &statement)
		resource := string(statement.Resources[0])
		val, ok := cache[resource]
		if !ok {
			cache[resource] = &statement
			continue
		}
		val.Actions = append(val.Actions, statement.Actions...)
	}
	cleanedStatements := make([]*policies.ACLPolicyStatement, len(cache))
	counter := 0
	for _, cacheItem := range cache {
		// policyStatement := cacheItem
		cleanedStatements[counter] = cacheItem
		counter++
	}
	return cleanedStatements, nil
}

func (v *permissionsStateVirtualizer) virualizeACLPolicyStatements(wrappers map[string]ACLPolicyStatementWrapper) ([]*policies.ACLPolicyStatement, error) {
	statements := make([]*policies.ACLPolicyStatement, 0)
	for _, wrapper := range wrappers {
		if len(wrapper.Statement.Resources) == 0 {
			continue
		} else {
			for _, resource := range wrapper.Statement.Resources {
				dest := policies.ACLPolicyStatement{}
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
	return v.virualizeACLPolicyStatementsWithASingleResource(statements)
}

func (v *permissionsStateVirtualizer) virtualize() (*PermissionsState, error) {
	newPermState := newPermissionsState()
	var err error
	var fobidItems []*policies.ACLPolicyStatement
	fobidItems, err = v.virualizeACLPolicyStatements(v.permissionState.permissions.forbid)
	if err != nil {
		return nil, err
	}
	extPermsState := newExtendedPermissionsState(newPermState)
	for _, fobidItem := range fobidItems {
		err := extPermsState.fobidACLPolicyStatements([]policies.ACLPolicyStatement{*fobidItem})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []*policies.ACLPolicyStatement
	permitItems, err = v.virualizeACLPolicyStatements(v.permissionState.permissions.permit)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := extPermsState.permitACLPolicyStatements([]policies.ACLPolicyStatement{*permitItem})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
