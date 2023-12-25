// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package policies

import (
	"sort"
	"strings"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

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

func SanitizeACPolicyStatement(version PolicyVersionString, acPolicyStatement *ACPolicyStatement) error {
	if !version.IsValid() || acPolicyStatement == nil {
		return authzAMErrors.ErrAccessManagementInvalidDataType
	}
	acPolicyStatement.Resources = sanitizeSlice(acPolicyStatement.Resources)
	acPolicyStatement.Actions = sanitizeSlice(acPolicyStatement.Actions)
	acPolicyStatement.Condition = strings.TrimSpace(acPolicyStatement.Condition)
	return nil
}

func ValidateACPolicyStatement(version PolicyVersionString, acPolicyStatement *ACPolicyStatement) (bool, error) {
	if !version.IsValid() || acPolicyStatement == nil {
		return false, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	var isValid bool
	var err error
	isValid, err = acPolicyStatement.Name.IsValid(version)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	for _, action := range acPolicyStatement.Actions {
		isValid, err = action.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	for _, resource := range acPolicyStatement.Resources {
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

func ValidateACPolicy(policy *ACPolicy) (bool, error) {
	if policy == nil || !policy.SyntaxVersion.IsValid() || policy.Type != PolicyACType {
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
	lists := [][]ACPolicyStatement{policy.Permit, policy.Forbid}
	for _, list := range lists {
		for _, acPolicyStatement := range list {
			isValid, err = ValidateACPolicyStatement(policy.SyntaxVersion, &acPolicyStatement)
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
