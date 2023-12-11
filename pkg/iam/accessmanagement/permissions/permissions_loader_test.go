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

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

func TestPermissionsLoaderRegisterPolicyValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-loader/register-policy/valid",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			caseName := c.Name()
			testDataCasePath := testDataVersionPath + "/" + caseName

			inputs, _ := os.ReadDir(testDataCasePath)
			for _, input := range inputs {
				inputName := input.Name()
				testDataCaseInputPath := testDataCasePath + "/" + inputName
				t.Run(strings.ToUpper(version+"-"+caseName+"-"+inputName), func(t *testing.T) {
					assert := assert.New(t)
					bArray, _ := os.ReadFile(testDataCaseInputPath)
					permLoader := newPermissionsLoader()
					registered, err := permLoader.registerPolicy(bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.True(registered, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(registered))
				})
			}
		}
	}
}

func TestPermissionsLoaderRegisterPolicyNotValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-loader/register-policy/notvalid",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			caseName := c.Name()
			testDataCasePath := testDataVersionPath + "/" + caseName

			inputs, _ := os.ReadDir(testDataCasePath)
			for _, input := range inputs {
				inputName := input.Name()
				testDataCaseInputPath := testDataCasePath + "/" + inputName
				t.Run(strings.ToUpper(version+"-"+caseName+"-"+inputName), func(t *testing.T) {
					assert := assert.New(t)
					bArray, _ := os.ReadFile(testDataCaseInputPath)
					permLoader := newPermissionsLoader()
					registered, err := permLoader.registerPolicy(bArray)
					assert.NotNil(err, "wrong result\nshould be not nil")
					assert.False(registered, "wrong result\ngot: %sshouldn't be true", spew.Sdump(registered))
				})
			}
		}
	}
}

func TestMiscellaneousPermissionsLoader(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		permissionsLoader := newPermissionsLoader()
		_, err = permissionsLoader.registerPolicy([]byte("\\)[\\S ]+\\s((?:(?"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementInvalidDataType", spew.Sdump(err))
	}
	{
		permissionsLoader := newPermissionsLoader()
		_, err = permissionsLoader.registerACLPolicy(nil)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permissionsLoader := newPermissionsLoader()
		aclPolicy := &policies.ACLPolicy{}
		_, err = permissionsLoader.registerACLPolicy(aclPolicy)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permissionsLoader := newPermissionsLoader()
		aclPolicy := &policies.ACLPolicy{}
		aclPolicy.Syntax = policies.PolicyV1
		aclPolicy.Type = policies.PolicyACLType
		_, err = permissionsLoader.registerACLPolicy(aclPolicy)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
}

func TestBuildPermissionsState(t *testing.T) {
	type TestStruct struct {
		Name             	string
		Path             	string
		InputFiles       	func() []string
		OutputFobidFile  	string
		OutputPermitFile 	string
		VirtualStateEnabled bool
	}
	tests := map[string][]TestStruct{
		string(policies.PolicyV1): {
			{
				"NOT-COMPRESSED",
				"./testdata/permissions-loader/build-raw-state",
				func() []string {
					return []string{"input-policy-1.json", "input-policy-2.json"}
				},
				"output-forbid.json",
				"output-permit.json",
				false,
			},
		},
	}
	for version, testGroup := range tests {
		for _, test := range testGroup {
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
					permissionsLoader := newPermissionsLoader()
					totPermitted, totFobidden := 0, 0
					for _, input := range test.InputFiles() {
						bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
						data := policies.ACLPolicy{}
						_ = json.Unmarshal(bArray, &data)
						var registered bool
						var err error
						registered, err = permissionsLoader.registerACLPolicy(&data)
						assert.True(registered, "wrong result\nshould be true")
						assert.Nil(err, "wrong result\nshould be nil")
						totPermitted += len(data.Permit)
						totFobidden += len(data.Forbid)
					}

					var err error

					permState, _ := permissionsLoader.buildPermissionsState(true)

					forbidList := permState.GetForbidItems()
					err = helperToComparePolicyStatementWrappers(testDataCasePath+"/"+test.OutputFobidFile, forbidList)
					assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))

					permitList := permState.GetPermitItems()
					err = helperToComparePolicyStatementWrappers(testDataCasePath+"/"+test.OutputPermitFile, permitList)
					assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
				})
			}
		}
	}
}
