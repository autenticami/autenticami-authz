// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"

	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
	"github.com/autenticami/autenticami-authz/pkg/extensions/text"

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

func (v *permissionsStateVirtualizer) splitWrapperByResource(output map[string]ACPolicyStatementWrapper, wrapper *ACPolicyStatementWrapper) error {
	for _, resource := range wrapper.Statement.Resources {
		dest := policies.ACPolicyStatement{}
		err := copier.Copy(&dest, &wrapper.Statement)
		if err != nil {
			return err
		}
		dest.Name = policies.PolicyLabelString((strings.Replace(uuid.NewString(), "-", "", -1)))
		if len(dest.Resources) > 1 {
			dest.Resources = []policies.UURString{resource}
		}
		wrapper, err := createACPolicyStatementWrapper(&dest)
		if err != nil {
			return err
		}
		if _, ok := output[wrapper.StatmentHashed]; ok {
			continue
		}
		output[wrapper.StatmentHashed] = *wrapper
	}
	return nil
}

func (v *permissionsStateVirtualizer) splitWrappersByResource(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	output := map[string]ACPolicyStatementWrapper{}
	for _, wrapper := range wrappers {
		if len(wrapper.Statement.Resources) == 0 {
			continue
		}
		err := v.splitWrapperByResource(output, &wrapper)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) groupWrappersByConditionalUniqeResource(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	cache := map[string]*policies.ACPolicyStatement{}
	for _, wrapper := range wrappers {
		statement := wrapper.Statement
		if len(statement.Resources) > 1 {
			return nil, authzErrors.ErrGeneric
		}
		err := policies.SanitizeACPolicyStatement(v.syntaxVersion, &statement)
		if err != nil {
			return nil, err
		}
		resourceKey := fmt.Sprintf("%s-%s", string(statement.Resources[0]), text.CreateStringHash(statement.Condition))
		if _, ok := cache[resourceKey]; !ok {
			cache[resourceKey] = &statement
			continue
		}
		cachedStatement := cache[resourceKey]
		cachedStatement.Actions = append(cachedStatement.Actions, statement.Actions...)
		err = policies.SanitizeACPolicyStatement(v.syntaxVersion, cachedStatement)
		if err != nil {
			return nil, err
		}
	}
	output := map[string]ACPolicyStatementWrapper{}
	for _, statement := range cache {
		wrapper, err := createACPolicyStatementWrapper(statement)
		if err != nil {
			return nil, err
		}
		output[wrapper.StatmentHashed] = *wrapper
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) organiseWrappersByViewType(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	output := map[string]ACPolicyStatementWrapper{}
	for key := range wrappers {
		wrapper := wrappers[key]
		if len(wrapper.Statement.Resources) > 1 {
			return nil, authzErrors.ErrGeneric
		}
		for _, action := range wrapper.Statement.Actions {
			dest := policies.ACPolicyStatement{}
			err := copier.Copy(&dest, &wrapper.Statement)
			if err != nil {
				return nil, err
			}
			dest.Name = policies.PolicyLabelString((strings.Replace(uuid.NewString(), "-", "", -1)))
			dest.Actions = []policies.ActionString{action}
			wrapper, err := createACPolicyStatementWrapper(&dest)
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

func (v *permissionsStateVirtualizer) virualizeACPolicyStatements(wrappers map[string]ACPolicyStatementWrapper, isCombined bool) ([]ACPolicyStatementWrapper, error) {
	var err error
	var outputMap map[string]ACPolicyStatementWrapper
	outputMap, err = v.splitWrappersByResource(wrappers)
	if err != nil {
		return nil, err
	}
	outputMap, err = v.groupWrappersByConditionalUniqeResource(outputMap)
	if err != nil {
		return nil, err
	}
	if !isCombined {
		outputMap, err = v.organiseWrappersByViewType(outputMap)
		if err != nil {
			return nil, err
		}
	}
	output := make([]ACPolicyStatementWrapper, len(outputMap))
	counter := 0
	for key := range outputMap {
		output[counter] = outputMap[key]
		counter++
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) virtualize(isCombined bool) (*PermissionsState, error) {
	newPermState := newPermissionsState()
	var err error
	var fobidItems []ACPolicyStatementWrapper
	fobidItems, err = v.virualizeACPolicyStatements(v.permissionState.permissions.forbid, isCombined)
	if err != nil {
		return nil, err
	}
	extPermsState := newExtendedPermissionsState(newPermState)
	for _, fobidItem := range fobidItems {
		err := extPermsState.fobidACPolicyStatements([]policies.ACPolicyStatement{fobidItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []ACPolicyStatementWrapper
	permitItems, err = v.virualizeACPolicyStatements(v.permissionState.permissions.permit, isCombined)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := extPermsState.permitACPolicyStatements([]policies.ACPolicyStatement{permitItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
