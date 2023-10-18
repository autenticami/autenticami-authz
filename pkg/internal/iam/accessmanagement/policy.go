// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	_ "embed"
	"fmt"
	"regexp"

	"github.com/autenticami/autenticami-authz/pkg/internal/core"
)

// A resource is uniquely identified with an ARNString (Applicative Resource Name) which looks like uur:581616507495:default:hr-app:time-management:people/*.
// REF: https://docs.autenticami.com/accounts/projects/resources/

const (
	arnFormatString    = "uur:%s:%s:%s:%s:%s"
	actionFormatString = "%s:%s"
)

type ARNString core.WildcardString

type UUR struct {
	account        core.WildcardString
	tenant         core.WildcardString
	project        core.WildcardString
	domain         core.WildcardString
	resource       core.WildcardString
	resourceFilter core.WildcardString
}

// An action is an operation that can affect more than one resource in the context of one or more tenants.
// REF: https://docs.autenticami.com/accounts/projects/actions/

type ActionString core.WildcardString

type Action struct {
	Resource core.WildcardString
	Action   core.WildcardString
}

type (
	// PolicyVersionString represents a valid policy version
	PolicyVersionString string
	// PolicyTypeString represents a valid policy type
	PolicyTypeString string
	// PolicyLabelString represents a valid policy label
	PolicyLabelString string
)

const (
	PolicyV20220721 PolicyVersionString = "2022-07-21"

	PolicyACLType PolicyTypeString = "ACL"

	PolicyTrustIdentityType PolicyTypeString = "PTI"
)

// A Policy defines a list of policy statements that can be allowed or denied.
// REF: https://docs.autenticami.com/access-management/policies/

type Policy struct {
	Version PolicyVersionString `json:"Version"`
	Type    PolicyTypeString    `json:"Type"`
}

// An Access Control List Policy (ACL) lists the actions that can/cannot be performed and the resourcers those actions can affect.
// REF: https://docs.autenticami.com/access-management/permissions-policies/#access-control-list-policy

type ACLPolicy struct {
	Policy
	Label       PolicyLabelString `json:"Label,omitempty"`
	Description string            `json:"Description,omitempty"`
	Permit      []PolicyStatement `json:"Permit,omitempty"`
	Forbid      []PolicyStatement `json:"Forbid,omitempty"`
}

//go:embed data/acl-policy-schema.json
var aclPolicySchema []byte

// A policy statement list acctions associated to resources.
// REF: https://docs.autenticami.com/access-management/permissions-policies/#policy-statement

type PolicyStatement struct {
	Label     PolicyLabelString `json:"Label,omitempty"`
	Actions   []ActionString    `json:"Actions"`
	Resources []ARNString       `json:"Resources"`
}

func isValidPattern(pattern string, s string) (bool, error) {
	regex := pattern
	matched, err := regexp.MatchString(regex, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func findStringSubmatch(pattern string, s string) map[string]string {
	myExp := regexp.MustCompile(pattern)
	match := myExp.FindStringSubmatch(s)
	result := make(map[string]string)
	for i, name := range myExp.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	return result
}

func sanitizeTokenName(value string) string {
	sanitizedValue := value
	if len(value) == 0 {
		sanitizedValue = "*"
	}
	return sanitizedValue
}

func (a ARNString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV20220721:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		cNumber := `\d{10,14}`
		cResourceFilterSlashHyphenName := fmt.Sprintf(`(?P<resource>%s+)(\/(?P<resourcefilter>%s))*`, cHyphenName, cSlashHyphenName)
		regex := fmt.Sprintf("^uur:(?P<account>(%s)?):(?P<tenant>(%s)?):(?P<project>(%s)?):(?P<domain>(%s)?):(%s)?$", cNumber, cHyphenName, cHyphenName, cSlashHyphenName, cResourceFilterSlashHyphenName)
		return regex, nil
	default:
		return "", ErrAccessManagementUnsupportedVersion
	}
}

func (a ARNString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV20220721:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, ErrAccessManagementUnsupportedVersion
	}
}

func (a ARNString) Parse(version PolicyVersionString) (*UUR, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, ErrAccessManagementInvalidARN
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &UUR{
		account:        core.WildcardString(sanitizeTokenName(result["account"])),
		tenant:         core.WildcardString(sanitizeTokenName(result["tenant"])),
		project:        core.WildcardString(sanitizeTokenName(result["project"])),
		domain:         core.WildcardString(sanitizeTokenName(result["domain"])),
		resource:       core.WildcardString(sanitizeTokenName(result["resource"])),
		resourceFilter: core.WildcardString(sanitizeTokenName(result["resourcefilter"])),
	}, nil
}

func (a ActionString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV20220721:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		regex := fmt.Sprintf("^(?P<resource>(%s)?):(?P<action>(%s)?)$", cHyphenName, cHyphenName)
		return regex, nil
	default:
		return "", ErrAccessManagementUnsupportedVersion
	}
}

func (a ActionString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV20220721:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, ErrAccessManagementUnsupportedVersion
	}
}

func (a ActionString) Parse(version PolicyVersionString) (*Action, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, ErrAccessManagementInvalidARN
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &Action{
		Resource: core.WildcardString(sanitizeTokenName(result["resource"])),
		Action:   core.WildcardString(sanitizeTokenName(result["action"])),
	}, nil
}

func (p PolicyVersionString) IsValid() bool {
	return p == PolicyV20220721
}

func (p PolicyTypeString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV20220721:
		return p == PolicyACLType || p == PolicyTrustIdentityType, nil
	default:
		return false, ErrAccessManagementUnsupportedVersion
	}
}

func (p PolicyLabelString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV20220721:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		regex := fmt.Sprintf("^((%s)?)$", cSlashHyphenName)
		return regex, nil
	default:
		return "", ErrAccessManagementUnsupportedVersion
	}
}

func (p PolicyLabelString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV20220721:
		pattern, err := p.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(p))
	default:
		return false, ErrAccessManagementUnsupportedVersion
	}
}

func validatePolicyStatement(version PolicyVersionString, policyStatement *PolicyStatement) (bool, error) {
	if !version.IsValid() || policyStatement == nil {
		return false, ErrAccessManagementInvalidDataType
	}
	var isValid bool
	var err error
	isValid, err = policyStatement.Label.IsValid(version)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	for _, action := range policyStatement.Actions {
		isValid, err = action.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	for _, resource := range policyStatement.Resources {
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

func validateACLPolicy(policy *ACLPolicy) (bool, error) {
	if policy == nil || !policy.Version.IsValid() || policy.Type != PolicyACLType {
		return false, nil
	}
	var isValid bool
	var err error
	isValid, err = policy.Label.IsValid(policy.Version)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	lists := [][]PolicyStatement{policy.Permit, policy.Forbid}
	for _, list := range lists {
		for _, policyStatement := range list {
			isValid, err = validatePolicyStatement(policy.Version, &policyStatement)
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
