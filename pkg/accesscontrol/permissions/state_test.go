// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/accesscontrol/errors"
)

func helperToCompareACPolicyStatementWrappers(file string, inputList []ACPolicyStatementWrapper) error {
	uniqueFobid := make(map[string]bool)
	for _, forbid := range inputList {
		key := forbid.StatmentHashed
		if uniqueFobid[key] {
			return errors.New("duplicated key: " + spew.Sdump(key))
		}
		uniqueFobid[key] = true
	}
	bArray, _ := os.ReadFile(file)
	data := []policies.ACPolicyStatement{}
	_ = json.Unmarshal(bArray, &data)
	if len(data) != len(inputList) {
		return errors.New("missing key as size does not match")
	}
	for _, forbid := range data {
		fobidWrapper, _ := createACPolicyStatementWrapper(&forbid)
		key := fobidWrapper.StatmentHashed
		if !uniqueFobid[key] {
			return errors.New("missing key: " + spew.Sdump(key))
		}
	}
	return nil
}

func TestCreatePermissionsState(t *testing.T) {
	tests := map[string]struct {
		Name             string
		Path             string
		InputFiles       func() []string
		OutputFobidFile  string
		OutputPermitFile string
	}{
		string(policies.PolicyV1): {
			"RAW-STATE",
			"./testdata/permissions-states/create-state",
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

func TestMiscellaneousPermissionsState(t *testing.T) {
	assert := assert.New(t)
	{
		_, err := createACPolicyStatementWrapper(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(errors.Is(err, authzAMErrors.ErrAccesscontrolInvalidDataType), "wrong result\ngot: %sshould be of type ErrJSONSchemaValidation", spew.Sdump(err))
	}
	{
		permState := newPermissionsState()
		extPermsState := newExtendedPermissionsState(permState)
		err := extPermsState.fobidACPolicyStatements(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be not nil")
	}
	{
		permState := newPermissionsState()
		extPermsState := newExtendedPermissionsState(permState)
		err := extPermsState.permitACPolicyStatements(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be not nil")
	}
}
