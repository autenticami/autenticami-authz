// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestJSONUnmarshaling(t *testing.T) {
	tests := map[string]struct {
		Path       string
		InputFiles func() []string
		Validate   func(policy *ACLPolicy) bool
	}{
		string(PolicyV1): {
			"./testdata/policies/marshaling",
			func() []string {
				return []string{"input-policy-1.json"}
			},
			func(policy *ACLPolicy) bool {
				return policy.Syntax == PolicyV1
			},
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			testDataCasePath := testDataVersionPath + "/" + name
			t.Run(strings.ToUpper(version+"-"+name), func(t *testing.T) {
				assert := assert.New(t)

				for _, input := range test.InputFiles() {
					bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
					assert.True(json.Valid(bArray), "wrong result\nJSON must be valid")

					data := ACLPolicy{}
					err := json.Unmarshal(bArray, &data)
					assert.Nil(err, "wrong result\nshould be nil")

					got := test.Validate(&data)
					assert.True(got, "wrong result\n policy is not valid")
				}
			})
		}
	}
}

func TestARNNotValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidaccountnumber ARNString = "581616507495"
			var defaultvalidtenantname ARNString = "my-tenant"
			var defaultvalidprojectname ARNString = "my-app"
			var defaultvaliddomainname ARNString = "my-domain"
			var defaultvalidresource ARNString = "resource/latest"
			notValidNames := []ARNString{
				"-n",
				"n-",
				"-n-",
				"n ",
				"-n/n",
				"n/n-",
				"-n/n-",
				"n//n",
				"n/n",
				"nn?9",
				"nn9 a",
				"nn9:a1",
			}
			notValidNumbers := []ARNString{
				"581",
				"5816 16507496",
				"5816A16507496",
				"5816B16507496",
				"58161/6507497",
				"58161-6507497",
			}
			notValidResources := []ARNString{
				" r",
				"r ",
				"r r",
				"r//r",
				"r/r//r",
				"r-/r",
				"-rr/r",
				"-r r/r",
				"r-r-/r-r",
				"-r-r/r/r",
				"r -r/r-r/r",
				"-r-r/r-r/r-r",
			}
			notValidDomains := notValidResources
			arns := []ARNString{
				"uur:581616507495:default:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:default:!!:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:default:hr-app:!!:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:!!:hr-app:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:!!:default:hr-app:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
			}
			// Accounts combinations
			for _, notValidNumber := range notValidNumbers {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, notValidNumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Tenants combinations
			for _, notValidTenant := range notValidNames {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, notValidTenant, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Application combinations
			for _, notValidApplicationName := range notValidNames {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, notValidApplicationName, defaultvaliddomainname, defaultvalidresource)))
			}
			// Domain combinations
			for _, notValidDomain := range notValidDomains {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, notValidDomain, defaultvalidresource)))
			}
			// Resources combinations
			for _, notValidResource := range notValidResources {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, notValidResource)))
			}
			for _, uur := range arns {
				got, _ := uur.IsValid(version)
				assert.False(got, "wrong result\ngot: %sshouldn't be a valid uur", spew.Sdump(uur))
			}
			arnStrings := []ARNString{
				"ar n:000111023455:default1:hr-app1:time-management1:people/1",
				"aarn:000111023455:default1:hr-app1:time-management1:people/1",
				"uur:000111023455:default1:!!:time-management1:people/1",
				"uur:000111023455:default:hr-app1:time-management1:people/ 1",
			}
			for _, arnString := range arnStrings {
				_, err := arnString.Parse(version)
				assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				assert.True(errors.Is(err, ErrAccessManagementInvalidARN), "wrong result\ngot: %sshould be of type ErrInvalidAction", spew.Sdump(err))
			}
		})
	}
}

func TestARNValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidaccountnumber ARNString = "581616507495"
			var defaultvalidtenantname ARNString = "my-tenant"
			var defaultvalidprojectname ARNString = "my-app"
			var defaultvaliddomainname ARNString = "my-domain"
			var defaultvalidresource ARNString = "resource/latest"
			validNames := []ARNString{
				"",
				"n",
				"nn",
				"nn9",
				"nn9-a",
				"nn9-a1",
				"*",
				"nn9*a",
				"nn9*a1",
				"nn9*a1*",
				"*nn9*a1*",
			}
			validNumbers := []ARNString{
				"",
				"581616507496",
				"581616507497",
			}
			validResources := []ARNString{
				"",
				"r",
				"r-r",
				"*r-r",
				"r-r*",
				"r*r",
				"*r-r*",
				"r/r",
				"r-r/r",
				"r-r/r-r",
				"r*r/r-r",
				"r-r/r*r",
				"r*r/r*r",
				"r-r/r/r",
				"r-r/r-r/r",
				"r-r/r-r/r-r",
			}
			validDomains := validResources
			arns := []ARNString{
				"uur:::::",
				"uur:581616507495:default:hr-app:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:de*ault:hr-ap*p:time-management:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:def*ult:hr-ap*p:time-managem*ent:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defa*lt:hr-ap*p:time-managem*ent:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defau*t:hr-ap*p:time-managem*ent:people/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defaul*:hr-ap*p:time-managem*ent:*pe*rson*/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:*efault:hr-ap*p:time-managem*ent:*pe*rson*/*bc182*146-1598-4fde-99aa-b2d4d08bc1e2",
			}
			// Accounts combinations
			for _, validNumber := range validNumbers {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, validNumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Tenants combinations
			for _, validTenant := range validNames {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, validTenant, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Application combinations
			for _, validApplicationName := range validNames {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, validApplicationName, defaultvaliddomainname, defaultvalidresource)))
			}
			// Domain combinations
			for _, validDomain := range validDomains {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, validDomain, defaultvalidresource)))
			}
			// Resources combinations
			for _, validResource := range validResources {
				arns = append(arns, ARNString(fmt.Sprintf(arnFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, validResource)))
			}
			for _, uur := range arns {
				got, _ := uur.IsValid(version)
				assert.True(got, "wrong result\ngot: %should be a valid uur", spew.Sdump(uur))
			}
			arnStringItems := [][]string{
				{"uur:000111023455:default1:hr-app1:time-management1:people/1", "000111023455", "default1", "hr-app1", "time-management1", "people", "1"},
				{"uur:000111023455:default1:hr-app1:time-management1:people/role/employee/1", "000111023455", "default1", "hr-app1", "time-management1", "people", "role/employee/1"},
			}
			for _, arnStringItem := range arnStringItems {
				arnstring := ARNString(arnStringItem[0])
				uur, err := arnstring.Parse(version)
				assert.Nil(err, "wrong result\ngot: should be nil")
				var got, want string
				want = arnStringItem[1]
				got = string(uur.account)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = arnStringItem[2]
				got = string(uur.tenant)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = arnStringItem[3]
				got = string(uur.project)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = arnStringItem[4]
				got = string(uur.domain)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = arnStringItem[5]
				got = string(uur.resource)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = arnStringItem[6]
				got = string(uur.resourceFilter)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
			}
		})
	}
}

func TestActionsNotValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidprojectname ActionString = "people"
			var defaultvaliddomainname ActionString = "Read"
			notValidNames := []ActionString{
				"-n",
				"n-",
				"-n-",
				"n ",
				"-n/n",
				"n/n-",
				"-n/n-",
				"n//n",
				"n/n",
				"nn?9",
				"nn9 a",
				"nn9:a1",
			}
			actions := []ActionString{
				"!",
				"!:Read",
				"people:!",
				"!:!",
			}
			// Resources combinations
			for _, notValidName := range notValidNames {
				actions = append(actions, ActionString(fmt.Sprintf(actionFormatString, notValidName, defaultvaliddomainname)))
			}
			// Actions combinations
			for _, notValidName := range notValidNames {
				actions = append(actions, ActionString(fmt.Sprintf(actionFormatString, defaultvalidprojectname, notValidName)))
			}
			for _, action := range actions {
				got, _ := action.IsValid(version)
				assert.False(got, "wrong result\ngot: %sshouldn't be a valid action", spew.Sdump(action))
			}
			actionStrings := []ActionString{
				"",
				"@:Read",
				"people:@",
				"@:@",
			}
			for _, actionString := range actionStrings {
				_, err := actionString.Parse(version)
				assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				assert.False(errors.Is(err, ErrAccessManagementInvalidAction), "wrong result\ngot: %sshould be of type ErrInvalidAction", spew.Sdump(err))
			}
		})
	}
}

func TestActionsValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidprojectname ActionString = "people"
			var defaultvaliddomainname ActionString = "Read"
			validNames := []ActionString{
				"n",
				"nn",
				"nn9",
				"nn9-a",
				"nn9-a1",
				"*",
				"nn9*a",
				"nn9*a1",
				"nn9*a1*",
				"*nn9*a1*",
			}
			actions := []ActionString{
				"people:Read",
				":",
			}
			// Application combinations
			for _, validName := range validNames {
				actions = append(actions, ActionString(fmt.Sprintf(actionFormatString, validName, defaultvaliddomainname)))
			}
			// Domain combinations
			for _, validName := range validNames {
				actions = append(actions, ActionString(fmt.Sprintf(actionFormatString, defaultvalidprojectname, validName)))
			}
			for _, action := range actions {
				got, _ := action.IsValid(version)
				assert.True(got, "wrong result\ngot: %sshould be of a valid action", spew.Sdump(action))
			}
			actionStringItems := [][]string{
				{"people:Read", "people", "Read"},
				{"people:", "people", "*"},
				{"people:*", "people", "*"},
				{":Read", "*", "Read"},
				{"*:Read", "*", "Read"},
			}
			for _, actionStringItem := range actionStringItems {
				actionstring := ActionString(actionStringItem[0])
				action, err := actionstring.Parse(version)
				assert.Nil(err, "wrong result\ngot: should be nil")
				var got, want string
				want = actionStringItem[1]
				got = string(action.Resource)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = actionStringItem[2]
				got = string(action.Action)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
			}
		})
	}
}

func TestPolicyNotValid(t *testing.T) {
	assert := assert.New(t)
	var isValid bool
	var err error
	{
		isValid, err = validateACLPolicy(nil)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.Syntax = PolicyV1
		policy.Type = PolicyTypeString("X")
		isValid, err = validateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))

		policy.Type = PolicyACLType
		policy.Label = "This is not valid as there are spaces"
		isValid, err = validateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.Syntax = PolicyV1
		policy.Type = PolicyACLType
		policy.Label = "PeopleBaseReader"
		policy.Permit = []PolicyStatement{
			{
				Label: "People Base Reader",
			},
		}
		isValid, err = validateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.Syntax = PolicyV1
		policy.Type = PolicyACLType
		policy.Label = "PeopleBaseReader"
		policy.Permit = []PolicyStatement{
			{
				Label: "PeopleBaseReader",
				Actions: []ActionString{
					"people:ListEmployee",
					"people:ReadEmployee",
				},
				Resources: []ARNString{
					"uur:581616507495:default:hr-app:organisation:people/*",
				},
			},
		}
		isValid, err = validateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(isValid))
	}
	{
		isValid, err = validatePolicyStatement(PolicyVersionString("0000-00-00"), nil)
		assert.True(errors.Is(err, ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policyStatement := PolicyStatement{
			Label: "PeopleBaseReader",
			Actions: []ActionString{
				"people:ListEmployee",
				"people:ReadEmployee",
			},
			Resources: []ARNString{
				"uur:581616507495:default:hr-app:organisation:people/*",
			},
		}
		isValid, err = validatePolicyStatement(PolicyVersionString("0000-00-00"), &policyStatement)
		assert.True(errors.Is(err, ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policyStatement := PolicyStatement{
			Label: "PeopleBaseReader",
			Actions: []ActionString{
				"not a valid action",
			},
			Resources: []ARNString{
				"uur:581616507495:default:hr-app:organisation:people/*",
			},
		}
		isValid, err = validatePolicyStatement(PolicyV1, &policyStatement)
		assert.Nil(err, "wrong result\nshould be nil")
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policyStatement := PolicyStatement{
			Label: "PeopleBaseReader",
			Actions: []ActionString{
				"people:ListEmployee",
				"people:ReadEmployee",
			},
			Resources: []ARNString{
				"not a valid uur",
			},
		}
		isValid, err = validatePolicyStatement(PolicyV1, &policyStatement)
		assert.Nil(err, "wrong result\nshould be nil")
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
}

func TestMiscellaneousPolicies(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		_, err = isValidPattern("\\)[\\S ]+\\s((?:(?", "")
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		uur := ARNString("uur:000111023455:default:hr-app1:time-management1:people/1")
		_, err = uur.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = uur.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = uur.Parse(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		action := ActionString("people:Read")
		_, err = action.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = action.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = action.Parse(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		policyType := PolicyACLType
		isValid, _ := policyType.IsValid(PolicyV1)
		assert.True(isValid, "wrong result\ngot: %should be a valid uur", spew.Sdump(isValid))
	}
	{
		policyType := PolicyACLType
		_, err = policyType.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		policyLabel := PolicyLabelString("permit-hr/person/reader/any")
		_, err = policyLabel.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = policyLabel.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
}
