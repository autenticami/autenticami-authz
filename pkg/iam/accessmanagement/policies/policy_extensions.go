// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package policies

import (
	"sort"
	"strings"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

func ValidateACLPolicyStatement(version PolicyVersionString, aclPolicyStatement *ACLPolicyStatement) (bool, error) {
	if !version.IsValid() || aclPolicyStatement == nil {
		return false, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	var isValid bool
	var err error
	isValid, err = aclPolicyStatement.Name.IsValid(version)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	for _, action := range aclPolicyStatement.Actions {
		isValid, err = action.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	for _, resource := range aclPolicyStatement.Resources {
		isValid, err = resource.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	return true, nil
}

func sanitizeSlice[K ~string](source []K) []K {
	outputMap := map[K]struct{}{}
	for _, item := range source {
		if _, ok := outputMap[item]; ok {
			continue
		}
		outputMap[item] = struct{}{}
	}
	keys := make([]string, 0)
	for k := range outputMap {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	items := make([]K, len(keys))
	for i, key := range keys {
		items[i] = K(key)
	}
	return items
}

func SanitizeACLPolicyStatement(version PolicyVersionString, aclPolicyStatement *ACLPolicyStatement) error {
	if !version.IsValid() || aclPolicyStatement == nil {
		return authzAMErrors.ErrAccessManagementInvalidDataType
	}
	aclPolicyStatement.Resources = sanitizeSlice(aclPolicyStatement.Resources)
	aclPolicyStatement.Actions = sanitizeSlice(aclPolicyStatement.Actions)
	aclPolicyStatement.Condition = strings.TrimSpace(aclPolicyStatement.Condition)
	return nil
}

func ValidateACLPolicy(policy *ACLPolicy) (bool, error) {
	if policy == nil || !policy.SyntaxVersion.IsValid() || policy.Type != PolicyACLType {
		return false, nil
	}
	var isValid bool
	var err error
	isValid, err = policy.Name.IsValid(policy.SyntaxVersion)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	lists := [][]ACLPolicyStatement{policy.Permit, policy.Forbid}
	for _, list := range lists {
		for _, aclPolicyStatement := range list {
			isValid, err = ValidateACLPolicyStatement(policy.SyntaxVersion, &aclPolicyStatement)
			if err != nil {
				return false, err
			}
			if !isValid {
				return false, nil
			}
		}
	}
	return true, nil
}
