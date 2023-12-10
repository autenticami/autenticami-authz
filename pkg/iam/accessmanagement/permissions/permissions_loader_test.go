// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzAMErrors "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/errors"
)

func TestJsonSchemaValidationForValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-loader/validate-jsonschema/valid",
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
					isValid, err := isValidJSON(policies.ACLPolicySchema, bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.True(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(isValid))
				})
			}
		}
	}
}

func TestJsonSchemaValidationForNotValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-loader/validate-jsonschema/notvalid",
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
					isValid, err := isValidJSON(policies.ACLPolicySchema, bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				})
			}
		}
	}
}

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
		_, err = isValidJSON(nil, nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementJSONSchemaValidation), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementJSONSchemaValidation", spew.Sdump(err))
	}
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
