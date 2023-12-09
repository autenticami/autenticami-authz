// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func helperToComparePolicyStatementWrappers(file string, inputList []*PolicyStatementWrapper) error {
	uniqueFobid := make(map[string]bool)
	for _, forbid := range inputList {
		key := forbid.StatmentHashed
		if uniqueFobid[key] {
			return errors.New("duplicated key: " + spew.Sdump(key))
		}
		uniqueFobid[key] = true
	}
	bArray, _ := os.ReadFile(file)
	data := []policies.PolicyStatement{}
	_ = json.Unmarshal(bArray, &data)
	if len(data) != len(inputList) {
		return errors.New("missing key as size does not match")
	}
	for _, forbid := range data {
		fobidWrapper, _ := createPolicyStatementWrapper(&forbid)
		key := fobidWrapper.StatmentHashed
		if !uniqueFobid[key] {
			return errors.New("missing key: " + spew.Sdump(key))
		}
	}
	return nil
}

func TestPermissionsStateCreation(t *testing.T) {
	tests := map[string]struct {
		Name			 string
		Path       		 string
		InputFiles 		 func() []string
		OutputFobidFile  string
		OutputPermitFile string
	}{
		string(policies.PolicyV1): {
			"NOT-COMPRESSED",
			"./testdata/permissions-states/not-compressed",
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			testDataCasePath := testDataVersionPath + "/" + name
			t.Run(strings.ToUpper(version+"-"+test.Name+"-"+name), func(t *testing.T) {
				assert := assert.New(t)
				permState := newPermissionsState()
				totPermitted, totFobidden := 0, 0
				for _, input := range test.InputFiles() {
					bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
					data := policies.ACLPolicy{}
					_ = json.Unmarshal(bArray, &data)
					var err error
					err = permState.fobidACLPolicyStatements(data.Forbid)
					assert.Nil(err, "wrong result\nshould be nil")
					totPermitted += len(data.Permit)
					err = permState.permitACLPolicyStatements(data.Permit)
					assert.Nil(err, "wrong result\nshould be nil")
					totFobidden += len(data.Forbid)
				}

				var got, want int
				var err error

				forbidList := permState.GetForbidList()
				got = len(forbidList)
				want = totFobidden
				assert.Equal(got, want, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))

				err = helperToComparePolicyStatementWrappers(testDataCasePath + "/" + test.OutputFobidFile, forbidList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))


				permitList := permState.GetPermitList()
				got = len(permitList)
				want = totPermitted
				assert.Equal(got, want, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))

				err = helperToComparePolicyStatementWrappers(testDataCasePath + "/" + test.OutputPermitFile, permitList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))

			})
		}
	}
}

func TestMiscellaneousPermissionsState(t *testing.T) {
	assert := assert.New(t)
	{
		permState := newPermissionsState()
		err := permState.fobidACLPolicyStatements([]*policies.PolicyStatement{nil})
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permState := newPermissionsState()
		err := permState.permitACLPolicyStatements([]*policies.PolicyStatement{nil})
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
}
