// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"errors"

	"github.com/autenticami/autenticami-authz/pkg/extensions/files"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

// Permission options

type PermissionsEngineOptions struct {
	enableVirtualState bool
}

type PermissionsEngineOption func(permEngineSetting *PermissionsEngineOptions) error

func buildPermissionsEngineOptions(options ...PermissionsEngineOption) (*PermissionsEngineOptions, error) {
	permEngineSettings := PermissionsEngineOptions{
		enableVirtualState: true,
	}
	for _, option := range options {
		err := option(&permEngineSettings)
		if err != nil {
			return nil, err
		}
	}
	return &permEngineSettings, nil
}

func WithPermissionsEngineVirtualState(enableVirtualState bool) PermissionsEngineOption {
	return func(options *PermissionsEngineOptions) error {
		options.enableVirtualState = enableVirtualState
		return nil
	}
}

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://docs.autenticami.com/access-management/policies/

type PermissionsEngine struct {
	syntax           policies.PolicyVersionString
	permissionsState *PermissionsState
}

func NewPermissionsEngine() *PermissionsEngine {
	permEngine := &PermissionsEngine{
		syntax:           policies.PolicyLatest,
		permissionsState: newPermissionsState(),
	}
	return permEngine
}

func (e *PermissionsEngine) RegisterPolicy(bData []byte) (bool, error) {
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
	if !policy.SyntaxVersion.IsValid() {
		return false, errors.Join(authzAMErrors.ErrAccessManagementUnsupportedVersion, err)
	}
	switch policy.Type {
	case policies.PolicyACLType:
		isValid, err = files.IsValidJSON(policies.ACLPolicySchema, bData)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, authzErrors.ErrJSONSchemaValidation
		}
		aclPolicy := policies.ACLPolicy{}
		err = json.Unmarshal(bData, &aclPolicy)
		if err != nil {
			return false, errors.Join(authzErrors.ErrJSONDataMarshaling, err)
		}
		isValid, err = e.registerACLPolicy(&aclPolicy)
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

func (e *PermissionsEngine) registerACLPolicy(policy *policies.ACLPolicy) (bool, error) {
	if policy == nil || policy.Type != policies.PolicyACLType {
		return false, authzAMErrors.ErrAccessManagementUnsupportedDataType
	}
	isValid, err := policies.ValidateACLPolicy(policy)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	extPermsState := newExtendedPermissionsState(e.permissionsState)
	if len(policy.Permit) > 0 {
		err := extPermsState.permitACLPolicyStatements(policy.Permit)
		if err != nil {
			return false, err
		}
	}
	if len(policy.Forbid) > 0 {
		err := extPermsState.fobidACLPolicyStatements(policy.Forbid)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (e *PermissionsEngine) BuildPermissions(options ...PermissionsEngineOption) (*PermissionsState, error) {
	permEngineSettings, err := buildPermissionsEngineOptions(options...)
	if err != nil {
		return nil, err
	}
	if permEngineSettings.enableVirtualState {
		virtualizer := newPermissionsStateVirtualizer(e.permissionsState)
		return virtualizer.virtualize()
	}
	return e.permissionsState.clone()
}
