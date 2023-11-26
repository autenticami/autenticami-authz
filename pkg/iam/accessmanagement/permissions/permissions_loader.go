// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"errors"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
	"github.com/xeipuuv/gojsonschema"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
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
		return false, errors.Join(authzAMErrors.ErrAccessManagementJSONSchemaValidation, err)
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

func (d *permissionsLoader) registerPolicy(bData []byte) (bool, error) {
	if bData == nil {
		return false, authzErrors.ErrJSONDataMarshaling
	}
	var err error
	var isValid bool
	policy := policies.Policy{}
	err = json.Unmarshal(bData, &policy)
	if err != nil {
		return false, errors.Join(authzAMErrors.ErrAccessManagementInvalidDataType, err)
	}
	if !policy.Syntax.IsValid() {
		return false, errors.Join(authzAMErrors.ErrAccessManagementUnsupportedVersion, err)
	}
	switch policy.Type {
	case policies.PolicyACLType:
		aclPolicy := policies.ACLPolicy{}
		err := json.Unmarshal(bData, &aclPolicy)
		if err != nil {
			return false, errors.Join(authzErrors.ErrJSONDataMarshaling, err)
		}
		isValid, err = d.registerACLPolicy(&aclPolicy)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	default:
		return false, authzAMErrors.ErrAccessManagementUnsupportedDataType
	}
	return true, nil
}

func (d *permissionsLoader) registerACLPolicy(policy *policies.ACLPolicy) (bool, error) {
	if policy.Type != policies.PolicyACLType {
		return false, authzAMErrors.ErrAccessManagementUnsupportedDataType
	}
	isValid, err := policies.ValidateACLPolicy(policy)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	if len(policy.Permit) > 0 {
		err := d.permissionsState.allowACLPolicyStatements(policy.Permit)
		if err != nil {
			return false, err
		}
	}
	if len(policy.Forbid) > 0 {
		err := d.permissionsState.denyACLPolicyStatements(policy.Forbid)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (d *permissionsLoader) buildPermissionsState() (*PermissionsState, error) {
	return d.permissionsState, nil
}
