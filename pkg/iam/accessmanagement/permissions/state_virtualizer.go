// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"strings"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

type permissionsStateVirtualizer struct {
	syntaxVersion   policies.PolicyVersionString
	permissionState *PermissionsState
}

func newPermissionsStateVirtualizer(syntaxVersion policies.PolicyVersionString, permsState *PermissionsState) *permissionsStateVirtualizer {
	return &permissionsStateVirtualizer{
		syntaxVersion:   syntaxVersion,
		permissionState: permsState,
	}
}

func (v *permissionsStateVirtualizer) splitByResource(wrappers map[string]ACLPolicyStatementWrapper) (map[string]ACLPolicyStatementWrapper, error) {
	output := map[string]ACLPolicyStatementWrapper{}
	for _, wrapper := range wrappers {
		if len(wrapper.Statement.Resources) == 0 {
			continue
		}
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
			wrapper, err := createACLPolicyStatementWrapper(&dest)
			if err != nil {
				return nil, err
			}
			if _, ok := output[wrapper.StatmentHashed]; ok {
				continue
			}
			output[wrapper.StatmentHashed] = *wrapper
		}
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) groupByConditionalUniqeResource(wrappers map[string]ACLPolicyStatementWrapper) (map[string]ACLPolicyStatementWrapper, error) {
	cache := map[string]*policies.ACLPolicyStatement{}
	for _, wrapper := range wrappers {
		statement := wrapper.Statement
		if len(statement.Resources) > 1 {
			return nil, authzErrors.ErrGeneric
		}
		resource := string(statement.Resources[0])
		if _, ok := cache[resource]; !ok {
			err := policies.SanitizeACLPolicyStatement(v.syntaxVersion, &statement)
			if err != nil {
				return nil, err
			}
			cache[resource] = &statement
			continue
		}
		cachedStatement := cache[resource]
		cachedStatement.Actions = append(cachedStatement.Actions, statement.Actions...)
		err := policies.SanitizeACLPolicyStatement(v.syntaxVersion, cachedStatement)
		if err != nil {
			return nil, err
		}
	}
	output := map[string]ACLPolicyStatementWrapper{}
	for _, statement := range cache {
		wrapper, err := createACLPolicyStatementWrapper(statement)
		if err != nil {
			return nil, err
		}
		output[wrapper.StatmentHashed] = *wrapper
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) virualizeACLPolicyStatements(wrappers map[string]ACLPolicyStatementWrapper) ([]ACLPolicyStatementWrapper, error) {
	var err error
	var outputMap map[string]ACLPolicyStatementWrapper
	outputMap, err = v.splitByResource(wrappers)
	if err != nil {
		return nil, err
	}
	outputMap, err = v.groupByConditionalUniqeResource(outputMap)
	if err != nil {
		return nil, err
	}
	output := make([]ACLPolicyStatementWrapper, len(outputMap))
	counter := 0
	for key := range outputMap {
		output[counter] = outputMap[key]
		counter++
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) virtualize() (*PermissionsState, error) {
	newPermState := newPermissionsState()
	var err error
	var fobidItems []ACLPolicyStatementWrapper
	fobidItems, err = v.virualizeACLPolicyStatements(v.permissionState.permissions.forbid)
	if err != nil {
		return nil, err
	}
	extPermsState := newExtendedPermissionsState(newPermState)
	for _, fobidItem := range fobidItems {
		err := extPermsState.fobidACLPolicyStatements([]policies.ACLPolicyStatement{fobidItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []ACLPolicyStatementWrapper
	permitItems, err = v.virualizeACLPolicyStatements(v.permissionState.permissions.permit)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := extPermsState.permitACLPolicyStatements([]policies.ACLPolicyStatement{permitItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
