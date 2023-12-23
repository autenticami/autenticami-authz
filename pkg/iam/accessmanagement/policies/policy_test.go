// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package policies

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
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
				return policy.SyntaxVersion == PolicyV1
			},
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			if strings.ToLower(name) == ".ds_store" {
				continue
			}
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

func TestUURNotValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidaccountnumber UURString = "581616507495"
			var defaultvalidtenantname UURString = "my-tenant"
			var defaultvalidprojectname UURString = "my-app"
			var defaultvaliddomainname UURString = "my-domain"
			var defaultvalidresource UURString = "resource/latest"
			notValidNames := []UURString{
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
			notValidNumbers := []UURString{
				"581",
				"5816 16507496",
				"5816A16507496",
				"5816B16507496",
				"58161/6507497",
				"58161-6507497",
			}
			notValidResources := []UURString{
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
			uurs := []UURString{
				"uur:581616507495:default:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:default:!!:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:default:hr-app:!!:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:!!:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:!!:default:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
			}
			// Accounts combinations
			for _, notValidNumber := range notValidNumbers {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, notValidNumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Tenants combinations
			for _, notValidTenant := range notValidNames {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, notValidTenant, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Application combinations
			for _, notValidApplicationName := range notValidNames {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, notValidApplicationName, defaultvaliddomainname, defaultvalidresource)))
			}
			// Domain combinations
			for _, notValidDomain := range notValidDomains {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, notValidDomain, defaultvalidresource)))
			}
			// Resources combinations
			for _, notValidResource := range notValidResources {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, notValidResource)))
			}
			for _, uur := range uurs {
				got, _ := uur.IsValid(version)
				assert.False(got, "wrong result\ngot: %sshouldn't be a valid uur", spew.Sdump(uur))
			}
			uurStrings := []UURString{
				"ar n:000111023455:default1:hr-app1:time-management1:person/1",
				"auur:000111023455:default1:hr-app1:time-management1:person/1",
				"uur:000111023455:default1:!!:time-management1:person/1",
				"uur:000111023455:default:hr-app1:time-management1:person/ 1",
			}
			for _, uurString := range uurStrings {
				_, err := uurString.Parse(version)
				assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidUUR), "wrong result\ngot: %sshould be of type ErrInvalidAction", spew.Sdump(err))
			}
		})
	}
}

func TestUURValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidaccountnumber UURString = "581616507495"
			var defaultvalidtenantname UURString = "my-tenant"
			var defaultvalidprojectname UURString = "my-app"
			var defaultvaliddomainname UURString = "my-domain"
			var defaultvalidresource UURString = "resource/latest"
			validNames := []UURString{
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
			validNumbers := []UURString{
				"",
				"581616507496",
				"581616507497",
			}
			validResources := []UURString{
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
			uurs := []UURString{
				"uur:::::",
				"uur:581616507495:default:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:de*ault:hr-ap*p:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:def*ult:hr-ap*p:time-managem*ent:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defa*lt:hr-ap*p:time-managem*ent:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defau*t:hr-ap*p:time-managem*ent:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:defaul*:hr-ap*p:time-managem*ent:*pe*rson*/bc182146-1598-4fde-99aa-b2d4d08bc1e2",
				"uur:581616507495:*efault:hr-ap*p:time-managem*ent:*pe*rson*/*bc182*146-1598-4fde-99aa-b2d4d08bc1e2",
			}
			// Accounts combinations
			for _, validNumber := range validNumbers {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, validNumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Tenants combinations
			for _, validTenant := range validNames {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, validTenant, defaultvalidprojectname, defaultvaliddomainname, defaultvalidresource)))
			}
			// Application combinations
			for _, validApplicationName := range validNames {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, validApplicationName, defaultvaliddomainname, defaultvalidresource)))
			}
			// Domain combinations
			for _, validDomain := range validDomains {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, validDomain, defaultvalidresource)))
			}
			// Resources combinations
			for _, validResource := range validResources {
				uurs = append(uurs, UURString(fmt.Sprintf(uurFormatString, defaultvalidaccountnumber, defaultvalidtenantname, defaultvalidprojectname, defaultvaliddomainname, validResource)))
			}
			for _, uur := range uurs {
				got, _ := uur.IsValid(version)
				assert.True(got, "wrong result\ngot: %should be a valid uur", spew.Sdump(uur))
			}
			uurStringItems := [][]string{
				{"uur:000111023455:default1:hr-app1:time-management1:person/1", "000111023455", "default1", "hr-app1", "time-management1", "person", "1"},
				{"uur:000111023455:default1:hr-app1:time-management1:person/role/employee/1", "000111023455", "default1", "hr-app1", "time-management1", "person", "role/employee/1"},
			}
			for _, uurStringItem := range uurStringItems {
				uurstring := UURString(uurStringItem[0])
				uur, err := uurstring.Parse(version)
				assert.Nil(err, "wrong result\ngot: should be nil")
				var got, want string
				want = uurStringItem[1]
				got = string(uur.account)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = uurStringItem[2]
				got = string(uur.tenant)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = uurStringItem[3]
				got = string(uur.project)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = uurStringItem[4]
				got = string(uur.domain)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = uurStringItem[5]
				got = string(uur.resource)
				assert.Equal(want, got, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
				want = uurStringItem[6]
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
			var defaultvalidprojectname ActionString = "person"
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
				"person:!",
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
				"person:@",
				"@:@",
			}
			for _, actionString := range actionStrings {
				_, err := actionString.Parse(version)
				assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				assert.False(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidAction), "wrong result\ngot: %sshould be of type ErrInvalidAction", spew.Sdump(err))
			}
		})
	}
}

func TestActionsValid(t *testing.T) {
	versions := []PolicyVersionString{PolicyV1}
	for _, version := range versions {
		t.Run(strings.ToUpper(string(version)), func(t *testing.T) {
			assert := assert.New(t)
			var defaultvalidprojectname ActionString = "person"
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
				"person:Read",
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
				{"person:Read", "person", "Read"},
				{"person:", "person", "*"},
				{"person:*", "person", "*"},
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
		isValid, err = ValidateACLPolicy(nil)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.SyntaxVersion = PolicyV1
		policy.Type = PolicyTypeString("X")
		isValid, err = ValidateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))

		policy.Type = PolicyACLType
		policy.Name = "This is not valid as there are spaces"
		isValid, err = ValidateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.SyntaxVersion = PolicyV1
		policy.Type = PolicyACLType
		policy.Name = "person-base-reader"
		policy.Permit = []ACLPolicyStatement{
			{
				Name: "person Base Reader",
			},
		}
		isValid, err = ValidateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		policy := ACLPolicy{}
		policy.SyntaxVersion = PolicyV1
		policy.Type = PolicyACLType
		policy.Name = "person-base-reader"
		policy.Permit = []ACLPolicyStatement{
			{
				Name: "person-base-reader",
				Actions: []ActionString{
					"person:ListEmployee",
					"person:ReadEmployee",
				},
				Resources: []UURString{
					"uur:581616507495:default:hr-app:organisation:person/*",
				},
			},
		}
		isValid, err = ValidateACLPolicy(&policy)
		assert.Nil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(isValid))
	}
	{
		isValid, err = ValidateACLPolicyStatement(PolicyVersionString("0000-00-00"), nil)
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		aclPolicyStatement := ACLPolicyStatement{
			Name: "person-base-reader",
			Actions: []ActionString{
				"person:ListEmployee",
				"person:ReadEmployee",
			},
			Resources: []UURString{
				"uur:581616507495:default:hr-app:organisation:person/*",
			},
		}
		isValid, err = ValidateACLPolicyStatement(PolicyVersionString("0000-00-00"), &aclPolicyStatement)
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		aclPolicyStatement := ACLPolicyStatement{
			Name: "person-base-reader",
			Actions: []ActionString{
				"not a valid action",
			},
			Resources: []UURString{
				"uur:581616507495:default:hr-app:organisation:person/*",
			},
		}
		isValid, err = ValidateACLPolicyStatement(PolicyV1, &aclPolicyStatement)
		assert.Nil(err, "wrong result\nshould be nil")
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		aclPolicyStatement := ACLPolicyStatement{
			Name: "person-base-reader",
			Actions: []ActionString{
				"person:ListEmployee",
				"person:ReadEmployee",
			},
			Resources: []UURString{
				"not a valid uur",
			},
		}
		isValid, err = ValidateACLPolicyStatement(PolicyV1, &aclPolicyStatement)
		assert.Nil(err, "wrong result\nshould be nil")
		assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
}

func TestSanitizeACLPolicyStatement(t *testing.T) {
	assert := assert.New(t)
	{
		aclPolicyStatement := ACLPolicyStatement{
			Name: "Sample",
			Actions: []ActionString { "person:Read", "person:Read", "person:Delete" },
			Resources: []UURString { "uur:581616507495:default:hr-app:organisation:person/B", "uur:581616507495:default:hr-app:organisation:person/A", "uur:581616507495:default:hr-app:organisation:person/A" },
			Condition: " DateGreaterThan({{.Autenticami.TokenIssueTime}})' && DateLessThan('{{.Autenticami.CurrentTime}}': '2023-12-31T23:59:59Z') ",
		}
		err := SanitizeACLPolicyStatement(PolicyLatest, &aclPolicyStatement)
		assert.Nil(err, "wrong result\nerr should be nil and not %s", spew.Sdump(err))
		assert.Equal(2, len(aclPolicyStatement.Actions), "wrong result\npolicy actions len should be equale to 2")
		assert.Equal(ActionString("person:Delete"), aclPolicyStatement.Actions[0], "wrong result\npolicy action value")
		assert.Equal(ActionString("person:Read"), aclPolicyStatement.Actions[1], "wrong result\npolicy action value")
		assert.Equal(2, len(aclPolicyStatement.Resources), "wrong result\npolicy resources len should be equale to 2")
		assert.Equal(UURString("uur:581616507495:default:hr-app:organisation:person/A"), aclPolicyStatement.Resources[0], "wrong result\npolicy resource value")
		assert.Equal(UURString("uur:581616507495:default:hr-app:organisation:person/B"), aclPolicyStatement.Resources[1], "wrong result\npolicy resource value")
		assert.Equal("DateGreaterThan({{.Autenticami.TokenIssueTime}})' && DateLessThan('{{.Autenticami.CurrentTime}}': '2023-12-31T23:59:59Z')", aclPolicyStatement.Condition, "wrong result\npolicy condition value")
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
		uur := UURString("uur:000111023455:default:hr-app1:time-management1:person/1")
		_, err = uur.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = uur.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = uur.Parse(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		action := ActionString("person:Read")
		_, err = action.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = action.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = action.Parse(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		policyType := PolicyACLType
		isValid, _ := policyType.IsValid(PolicyV1)
		assert.True(isValid, "wrong result\ngot: %should be a valid uur", spew.Sdump(isValid))
	}
	{
		policyType := PolicyACLType
		_, err = policyType.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		policyLabel := PolicyLabelString("permit-hr/person/reader/any")
		_, err = policyLabel.getRegex(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
		_, err = policyLabel.IsValid(PolicyVersionString("0000-00-00"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementUnsupportedVersion), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementUnsupportedVersion", spew.Sdump(err))
	}
	{
		var policyTypeString PolicyTypeString
		isValid, _ := policyTypeString.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
		isValid, _ = policyTypeString.IsValid("0000-00-00")
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyTypeString PolicyTypeString
		isValid, _ := policyTypeString.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyTypeString PolicyTypeString = "Sample value"
		isValid, _ := policyTypeString.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
		isValid, _ = policyTypeString.IsValid("0000-00-00")
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyVersion PolicyVersionString
		isValid := policyVersion.IsValid()
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyVersion PolicyVersionString = "Sample value"
		isValid := policyVersion.IsValid()
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var uur UURString
		isValid, _ := uur.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var uur UURString = "Sample value"
		isValid, _ := uur.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
		isValid, _ = uur.IsValid("0000-00-00")
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyLable PolicyLabelString
		isValid, _ := policyLable.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
	{
		var policyLable PolicyLabelString = "Sample value"
		isValid, _ := policyLable.IsValid(PolicyV1)
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
		isValid, _ = policyLable.IsValid("0000-00-00")
		assert.False(isValid, "wrong result\ngot: %sshould be not valid", isValid)
	}
}
