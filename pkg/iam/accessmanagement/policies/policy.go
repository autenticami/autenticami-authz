// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package policies

import (
	_ "embed"
	"fmt"
	"regexp"

	"github.com/autenticami/autenticami-authz/pkg/extensions"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

// A resource is uniquely identified with an UURString (Applicative Resource Name) which looks like uur:581616507495:default:hr-app:time-management:person/*.
// REF: https://docs.autenticami.com/accounts/projects/resources/

const (
	uurFormatString    = "uur:%s:%s:%s:%s:%s"
	actionFormatString = "%s:%s"
)

type UURString extensions.WildcardString

type UUR struct {
	account        extensions.WildcardString
	tenant         extensions.WildcardString
	project        extensions.WildcardString
	domain         extensions.WildcardString
	resource       extensions.WildcardString
	resourceFilter extensions.WildcardString
}

// An action is an operation that can affect more than one resource in the context of one or more tenants.
// REF: https://docs.autenticami.com/accounts/projects/actions/

type ActionString extensions.WildcardString

type Action struct {
	Resource extensions.WildcardString
	Action   extensions.WildcardString
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
	PolicyV1     PolicyVersionString = "autenticami1"
	PolicyLatest PolicyVersionString = PolicyV1

	PolicyACLType PolicyTypeString = "ACL"

	PolicyTrustIdentityType PolicyTypeString = "PTI"
)

// A Policy defines a list of policy statements that can be allowed or denied.
// REF: https://docs.autenticami.com/access-management/policies/

type Policy struct {
	Syntax PolicyVersionString `json:"Syntax"`
	Type   PolicyTypeString    `json:"Type"`
}

// An Access Control List Policy (ACL) lists the actions that can/cannot be performed and the resourcers those actions can affect.
// REF: https://docs.autenticami.com/access-management/permissions-policies/#access-control-list-policy

type ACLPolicy struct {
	Policy
	Name   PolicyLabelString `json:"Name,omitempty"`
	Permit []*PolicyStatement `json:"Permit,omitempty"`
	Forbid []*PolicyStatement `json:"Forbid,omitempty"`
}

//go:embed data/acl-policy-schema.json
var ACLPolicySchema []byte

// A policy statement list actions associated to resources.
// REF: https://docs.autenticami.com/access-management/permissions-policies/#policy-statement

type PolicyStatement struct {
	Name      PolicyLabelString `json:"Name,omitempty"`
	Actions   []ActionString    `json:"Actions"`
	Resources []UURString       `json:"Resources"`
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

func (a UURString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		cHyphenExtendedName := `([a-zA-Z0-9\.@\*]+(-[a-zA-Z0-9\.@\*]+)*)`
		cSlashHyphenExtendedName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenExtendedName, cHyphenExtendedName)
		cNumber := `\d{10,14}`
		cResourceFilterSlashHyphenName := fmt.Sprintf(`(?P<resource>%s+)(\/(?P<resourcefilter>%s))*`, cHyphenName, cSlashHyphenExtendedName)
		regex := fmt.Sprintf("^uur:(?P<account>(%s)?):(?P<tenant>(%s)?):(?P<project>(%s)?):(?P<domain>(%s)?):(%s)?$", cNumber, cHyphenName, cHyphenName, cSlashHyphenName, cResourceFilterSlashHyphenName)
		return regex, nil
	default:
		return "", authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (a UURString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV1:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (a UURString) Parse(version PolicyVersionString) (*UUR, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, authzAMErrors.ErrAccessManagementInvalidUUR
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &UUR{
		account:        extensions.WildcardString(sanitizeTokenName(result["account"])),
		tenant:         extensions.WildcardString(sanitizeTokenName(result["tenant"])),
		project:        extensions.WildcardString(sanitizeTokenName(result["project"])),
		domain:         extensions.WildcardString(sanitizeTokenName(result["domain"])),
		resource:       extensions.WildcardString(sanitizeTokenName(result["resource"])),
		resourceFilter: extensions.WildcardString(sanitizeTokenName(result["resourcefilter"])),
	}, nil
}

func (a ActionString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		regex := fmt.Sprintf("^(?P<resource>(%s)?):(?P<action>(%s)?)$", cHyphenName, cHyphenName)
		return regex, nil
	default:
		return "", authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (a ActionString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV1:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (a ActionString) Parse(version PolicyVersionString) (*Action, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, authzAMErrors.ErrAccessManagementInvalidUUR
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &Action{
		Resource: extensions.WildcardString(sanitizeTokenName(result["resource"])),
		Action:   extensions.WildcardString(sanitizeTokenName(result["action"])),
	}, nil
}

func (p PolicyVersionString) IsValid() bool {
	return p == PolicyV1
}

func (p PolicyTypeString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV1:
		return p == PolicyACLType || p == PolicyTrustIdentityType, nil
	default:
		return false, authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (p PolicyLabelString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		regex := fmt.Sprintf("^((%s)?)$", cSlashHyphenName)
		return regex, nil
	default:
		return "", authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func (p PolicyLabelString) IsValid(version PolicyVersionString) (bool, error) {
	switch version {
	case PolicyV1:
		pattern, err := p.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(p))
	default:
		return false, authzAMErrors.ErrAccessManagementUnsupportedVersion
	}
}

func validatePolicyStatement(version PolicyVersionString, policyStatement *PolicyStatement) (bool, error) {
	if !version.IsValid() || policyStatement == nil {
		return false, authzAMErrors.ErrAccessManagementInvalidDataType
	}
	var isValid bool
	var err error
	isValid, err = policyStatement.Name.IsValid(version)
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

func ValidateACLPolicy(policy *ACLPolicy) (bool, error) {
	if policy == nil || !policy.Syntax.IsValid() || policy.Type != PolicyACLType {
		return false, nil
	}
	var isValid bool
	var err error
	isValid, err = policy.Name.IsValid(policy.Syntax)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	lists := [][]*PolicyStatement{policy.Permit, policy.Forbid}
	for _, list := range lists {
		for _, policyStatement := range list {
			isValid, err = validatePolicyStatement(policy.Syntax, policyStatement)
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
