// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestJsonSchemaValidationForValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(PolicyV1): {
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
					isValid, err := isValidJSON(aclPolicySchema, bArray)
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
		string(PolicyV1): {
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
					isValid, err := isValidJSON(aclPolicySchema, bArray)
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
		string(PolicyV1): {
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
					permLoader, _ := newPermissionsLoader()
					registered, err := permLoader.RegisterPolicy(bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.True(registered, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(registered))
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
		assert.True(errors.Is(err, ErrAccessManagementJSONSchemaValidation), "wrong result\ngot: %sshould be of type ErrAccessManagementJSONSchemaValidation", spew.Sdump(err))
	}
	{
		permissionsLoader, _ := newPermissionsLoader()
		_, err = permissionsLoader.RegisterPolicy([]byte("\\)[\\S ]+\\s((?:(?"))
		assert.True(errors.Is(err, ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type ErrAccessManagementInvalidDataType", spew.Sdump(err))
	}
}
