// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	"encoding/json"
	"errors"

	pkgCore "github.com/autenticami/autenticami-authz/pkg/core"

	"github.com/xeipuuv/gojsonschema"
)

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/permissions-policies/

type permissionsLoader struct {
	permissionsState *PermissionsState
}

func isValidJSON(jsonSchme []byte, json []byte) (bool, error) {
	schemaLoader := gojsonschema.NewBytesLoader(jsonSchme)
	documentLoader := gojsonschema.NewBytesLoader(json)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, errors.Join(ErrAccessManagementJSONSchemaValidation, err)
	}
	if result.Valid() {
		return true, nil
	} else {
		return false, nil
	}
}

func newPermissionsLoader() (*permissionsLoader, error) {
	return &permissionsLoader{
		permissionsState: &PermissionsState{},
	}, nil
}

func (d *permissionsLoader) RegisterPolicy(bData []byte) (bool, error) {
	if bData == nil {
		return false, pkgCore.ErrJSONDataMarshaling
	}
	var err error
	var isValid bool
	policy := Policy{}
	err = json.Unmarshal(bData, &policy)
	if err != nil {
		return false, errors.Join(ErrAccessManagementInvalidDataType, err)
	}
	if !policy.Syntax.IsValid() {
		return false, errors.Join(ErrAccessManagementUnsupportedVersion, err)
	}
	switch policy.Type {
	case PolicyACLType:
		aclPolicy := ACLPolicy{}
		err := json.Unmarshal(bData, &aclPolicy)
		if err != nil {
			return false, errors.Join(pkgCore.ErrJSONDataMarshaling, err)
		}
		isValid, err = d.registerACLPolicy(&aclPolicy)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	default:
		return false, ErrAccessManagementUnsupportedDataType
	}
	return true, nil
}

func (d *permissionsLoader) registerACLPolicy(policy *ACLPolicy) (bool, error) {
	if policy.Type != PolicyACLType {
		return false, ErrAccessManagementUnsupportedDataType
	}
	isValid, err := validateACLPolicy(policy)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, ErrAccessManagementInvalidDataType
	}
	if len(policy.Permit) > 0 {
		err := d.permissionsState.AllowACLPolicyStatements(policy.Permit)
		if err != nil {
			return false, err
		}
	}
	if len(policy.Forbid) > 0 {
		err := d.permissionsState.DenyACLPolicyStatements(policy.Forbid)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (d *permissionsLoader) BuildPermissionsState() (*PermissionsState, error) {
	return d.permissionsState, nil
}
