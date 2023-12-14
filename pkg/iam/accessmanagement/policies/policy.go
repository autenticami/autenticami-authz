// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package policies

import (
	_ "embed"
	"fmt"
	"regexp"

	"github.com/autenticami/autenticami-authz/pkg/extensions/text"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

// A resource is uniquely identified with an UURString (Applicative Resource Name) which looks like uur:581616507495:default:hr-app:time-management:person/*.
// REF: https://docs.autenticami.com/accounts/projects/resources/

const (
	uurFormatString    = "uur:%s:%s:%s:%s:%s"
	actionFormatString = "%s:%s"
)

type UURString text.WildcardString

type UUR struct {
	account        text.WildcardString
	tenant         text.WildcardString
	project        text.WildcardString
	domain         text.WildcardString
	resource       text.WildcardString
	resourceFilter text.WildcardString
}

// An action is an operation that can affect more than one resource in the context of one or more tenants.
// REF: https://docs.autenticami.com/accounts/projects/actions/

type ActionString text.WildcardString

type Action struct {
	Resource text.WildcardString
	Action   text.WildcardString
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

// A Policy defines a list of policy statements that can be permited or forbidden.
// REF: https://docs.autenticami.com/access-management/policies/

type Policy struct {
	SyntaxVersion PolicyVersionString `json:"Syntax"`
	Type          PolicyTypeString    `json:"Type"`
}

// An Access Control List Policy (ACL) lists the actions that can/cannot be performed and the resourcers those actions can affect.
// REF: https://docs.autenticami.com/access-management/policies/#access-control-list-policy

type ACLPolicy struct {
	Policy
	Name   PolicyLabelString    `json:"Name,omitempty"`
	Permit []ACLPolicyStatement `json:"Permit,omitempty"`
	Forbid []ACLPolicyStatement `json:"Forbid,omitempty"`
}

//go:embed data/acl-policy-schema.json
var ACLPolicySchema []byte

// A policy statement list actions associated to resources.
// REF: https://docs.autenticami.com/access-management/policies/#policy-statement

type ACLPolicyStatement struct {
	Name      PolicyLabelString `json:"Name,omitempty"`
	Actions   []ActionString    `json:"Actions"`
	Resources []UURString       `json:"Resources"`
	Condition string            `json:"Condition,omitempty"`
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
	if len(a) == 0 {
		return false, nil
	}
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
		account:        text.WildcardString(sanitizeTokenName(result["account"])),
		tenant:         text.WildcardString(sanitizeTokenName(result["tenant"])),
		project:        text.WildcardString(sanitizeTokenName(result["project"])),
		domain:         text.WildcardString(sanitizeTokenName(result["domain"])),
		resource:       text.WildcardString(sanitizeTokenName(result["resource"])),
		resourceFilter: text.WildcardString(sanitizeTokenName(result["resourcefilter"])),
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
	if len(a) == 0 {
		return false, nil
	}
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
		Resource: text.WildcardString(sanitizeTokenName(result["resource"])),
		Action:   text.WildcardString(sanitizeTokenName(result["action"])),
	}, nil
}

func (p PolicyVersionString) IsValid() bool {
	return p == PolicyV1
}

func (p PolicyTypeString) IsValid(version PolicyVersionString) (bool, error) {
	if len(p) == 0 {
		return false, nil
	}
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
	if len(p) == 0 {
		return false, nil
	}
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
