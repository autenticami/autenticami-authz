// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

func TestJsonSchemaValidationForValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/extensions/files/validate-jsonschema/valid",
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
					isValid, err := IsValidJSON(policies.ACPolicySchema, bArray)
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
			"./testdata/extensions/files/validate-jsonschema/notvalid",
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
					isValid, err := IsValidJSON(policies.ACPolicySchema, bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				})
			}
		}
	}
}

func TestMiscellaneousPermissionsLoader(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		_, err = IsValidJSON(nil, nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(errors.Is(err, authzErrors.ErrJSONSchemaValidation), "wrong result\ngot: %sshould be of type ErrJSONSchemaValidation", spew.Sdump(err))
	}
}
