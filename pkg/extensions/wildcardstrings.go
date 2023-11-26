// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package extensions

import (
	"fmt"
	"regexp"
	"strings"
)

const wildcardChar = "*"

type WildcardString string

func convertWildcardStringToRegexp(wildcardString string) string {
	var pattern strings.Builder
	for i, literal := range strings.Split(wildcardString, wildcardChar) {
		if i > 0 {
			str := fmt.Sprintf(".%s", wildcardChar)
			pattern.WriteString(str)
		}
		pattern.WriteString(regexp.QuoteMeta(literal))
	}
	return pattern.String()
}

func compactWildcards(wildcardString string) string {
	return strings.ReplaceAll(wildcardString, fmt.Sprintf("%s%s", wildcardChar, wildcardChar), wildcardChar)
}

func (a WildcardString) wildcardMatch(value string, sanitized bool) bool {
	var pattern string
	aStr := compactWildcards(string(a))
	valueStr := compactWildcards(value)
	pattern = convertWildcardStringToRegexp(aStr)
	sanitizedValue := valueStr
	pattern = fmt.Sprintf("^%s$", pattern)
	if sanitized {
		sanitizedValue = strings.ReplaceAll(valueStr, wildcardChar, "")
	}
	result, _ := regexp.MatchString(pattern, sanitizedValue)
	return result
}

func (a WildcardString) WildcardEqual(value string) bool {
	aStr := compactWildcards(string(a))
	valueStr := compactWildcards(value)
	return aStr == valueStr
}

func (a WildcardString) WildcardInclude(value string) bool {
	aStr := string(a)
	if a.WildcardEqual(value) {
		return false
	}
	aSanitizedMatch := a.wildcardMatch(value, false)
	vSanitizedMatch := WildcardString(value).wildcardMatch(aStr, false)
	if strings.ReplaceAll(aStr, wildcardChar, "") == strings.ReplaceAll(value, wildcardChar, "") {
		greater := strings.Count(aStr, wildcardChar) > strings.Count(value, wildcardChar)
		return greater && aSanitizedMatch && vSanitizedMatch
	}
	return aSanitizedMatch && !vSanitizedMatch
}
