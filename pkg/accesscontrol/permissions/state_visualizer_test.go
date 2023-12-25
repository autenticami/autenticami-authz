// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestVirtualizeState(t *testing.T) {
	tests := []struct {
		Name             string
		Version          policies.PolicyVersionString
		Path             string
		Combined         bool
		InputFiles       func() []string
		OutputFobidFile  string
		OutputPermitFile string
	}{
		{
			"VIRTUAL-STATE-COMBINED-WITH-CONDITIONS",
			policies.PolicyV1,
			"./testdata/permissions-states/virtualize-state/combined/with-conditions",
			true,
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
		{
			"VIRTUAL-STATE-COMBINED-WITHOUT-CONDITIONS",
			policies.PolicyV1,
			"./testdata/permissions-states/virtualize-state/combined/without-conditions",
			true,
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
		{
			"VIRTUAL-STATE-UNCOMBINED-WITH-CONDITIONS",
			policies.PolicyV1,
			"./testdata/permissions-states/virtualize-state/uncombined/with-conditions",
			false,
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
		{
			"VIRTUAL-STATE-UNCOMBINED-WITHOUT-CONDITIONS",
			policies.PolicyV1,
			"./testdata/permissions-states/virtualize-state/uncombined/without-conditions",
			false,
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
	}
	for _, test := range tests {
		version := string(test.Version)
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			if strings.ToLower(name) == ".ds_store" {
				continue
			}
			testDataCasePath := testDataVersionPath + "/" + name
			t.Run(strings.ToUpper(version+"-"+test.Name+"-"+name), func(t *testing.T) {
				assert := assert.New(t)
				permState := newPermissionsState()
				totPermitted, totFobidden := 0, 0
				for _, input := range test.InputFiles() {
					bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
					data := policies.ACPolicy{}
					_ = json.Unmarshal(bArray, &data)
					var err error
					extPermsState := newExtendedPermissionsState(permState)
					err = extPermsState.fobidACPolicyStatements(data.Forbid)
					assert.Nil(err, "wrong result\nshould be nil")
					totPermitted += len(data.Permit)
					err = extPermsState.permitACPolicyStatements(data.Permit)
					assert.Nil(err, "wrong result\nshould be nil")
					totFobidden += len(data.Forbid)
				}

				var err error

				virtualizer := newPermissionsStateVirtualizer(policies.PolicyVersionString(version), permState)
				permState, err = virtualizer.virtualize(test.Combined)
				assert.Nil(err, "wrong result\nshould be nil")

				forbidList, _ := permState.GetACForbiddenPermissions()
				err = helperToCompareACPolicyStatementWrappers(testDataCasePath+"/"+test.OutputFobidFile, forbidList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))

				permitList, _ := permState.GetACPermittedPermissions()
				err = helperToCompareACPolicyStatementWrappers(testDataCasePath+"/"+test.OutputPermitFile, permitList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
			})
		}
	}
}
