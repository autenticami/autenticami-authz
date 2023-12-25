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

func TestPermissionsEngineBuildInvalidPermissions(t *testing.T) {
	{
		engine := NewPermissionsEngine()
		_, err := engine.RegisterPolicy(nil)
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		_, err := engine.RegisterPolicy([]byte{})
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"2022-08-08", "Type":"AC"}`
		_, err := engine.RegisterPolicy([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"autenticami1", "Type":"ABC"}`
		_, err := engine.RegisterPolicy([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"autenticami1", "Type":"AC", "Name": "12 3465 "}`
		_, err := engine.RegisterPolicy([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
}

func TestPermissionsEngineRegisterPolicy(t *testing.T) {
	engine := NewPermissionsEngine()
	jsonStr := `{"Syntax":"autenticami1", "Type":"AC", "Name": "person-base-reader"}`
	_, _ = engine.RegisterPolicy([]byte(jsonStr))
	permState, err := engine.BuildPermissions(WithPermissionsEngineVirtualState(false))
	assert.Nil(t, err, "Err should be nil")
	assert.Equal(t, len(permState.permissions.permit), 0, "Permit list should be empty")
	assert.Equal(t, len(permState.permissions.forbid), 0, "Forbid list should be empty")
}

func TestPermissionsEngineRegisterPolicyValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-engine/register-policy/valid/without-conditions",
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
					permLoader := NewPermissionsEngine()
					registered, err := permLoader.RegisterPolicy(bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.True(registered, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(registered))
				})
			}
		}
	}
}

func TestPermissionsEngineRegisterPolicyNotValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-engine/register-policy/notvalid/without-conditions",
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
					permLoader := NewPermissionsEngine()
					registered, err := permLoader.RegisterPolicy(bArray)
					assert.NotNil(err, "wrong result\nshould be not nil")
					assert.False(registered, "wrong result\ngot: %sshouldn't be true", spew.Sdump(registered))
				})
			}
		}
	}
}

func TestMiscellaneousPermissionsEngine(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		permissionsEngine := NewPermissionsEngine()
		_, err = permissionsEngine.RegisterPolicy([]byte("\\)[\\S ]+\\s((?:(?"))
		assert.True(errors.Is(err, authzAMErrors.ErrAccessManagementInvalidDataType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAccessManagementInvalidDataType", spew.Sdump(err))
	}
	{
		permissionsEngine := NewPermissionsEngine()
		_, err = permissionsEngine.registerACPolicy(nil)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permissionsEngine := NewPermissionsEngine()
		acPolicy := &policies.ACPolicy{}
		_, err = permissionsEngine.registerACPolicy(acPolicy)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permissionsEngine := NewPermissionsEngine()
		acPolicy := &policies.ACPolicy{}
		acPolicy.SyntaxVersion = policies.PolicyV1
		acPolicy.Type = policies.PolicyACType
		_, err = permissionsEngine.registerACPolicy(acPolicy)
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
}

func TestBuildPermissionsState(t *testing.T) {
	type TestStruct struct {
		Name                string
		Path                string
		InputFiles          func() []string
		OutputFobidFile     string
		OutputPermitFile    string
		VirtualStateEnabled bool
	}
	tests := map[string][]TestStruct{
		string(policies.PolicyV1): {
			{
				"RAW-STATE",
				"./testdata/permissions-engine/build-raw-state/without-conditions",
				func() []string {
					return []string{"input-policy-1.json", "input-policy-2.json"}
				},
				"output-forbid.json",
				"output-permit.json",
				false,
			},
			{
				"VIRTUAL-STATE",
				"./testdata/permissions-engine/build-virtual-state/without-conditions",
				func() []string {
					return []string{"input-policy-1.json", "input-policy-2.json"}
				},
				"output-forbid.json",
				"output-permit.json",
				true,
			},
			{
				"VIRTUAL-STATE",
				"./testdata/permissions-engine/build-virtual-state/with-conditions",
				func() []string {
					return []string{"input-policy-1.json", "input-policy-2.json"}
				},
				"output-forbid.json",
				"output-permit.json",
				true,
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
					permissionsEngine := NewPermissionsEngine()
					totPermitted, totFobidden := 0, 0
					for _, input := range test.InputFiles() {
						bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
						data := policies.ACPolicy{}
						_ = json.Unmarshal(bArray, &data)
						var registered bool
						var err error
						registered, err = permissionsEngine.registerACPolicy(&data)
						assert.True(registered, "wrong result\nshould be true")
						assert.Nil(err, "wrong result\nshould be nil")
						totPermitted += len(data.Permit)
						totFobidden += len(data.Forbid)
					}

					var err error

					permState, _ := permissionsEngine.BuildPermissions(WithPermissionsEngineVirtualState(test.VirtualStateEnabled))

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
}

func TestBuildPermissionsEngineOption(t *testing.T) {
	assert := assert.New(t)
	{
		expVirtualState := false
		expVirtualStateCombined := false
		options, err := buildPermissionsEngineOptions(WithPermissionsEngineVirtualState(expVirtualState), WithPermissionsEngineVirtualStateViewCombined(expVirtualStateCombined))
		assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
		assert.Equal(options.enableVirtualState, expVirtualState, "wrong result\nenableVirtualState should be%s", spew.Sdump(expVirtualState))
		assert.Equal(options.virtualStateViewCombined, expVirtualStateCombined, "wrong result\nexpVirtualStateCombined should be%s", spew.Sdump(expVirtualStateCombined))
	}
	{
		expVirtualState := true
		expVirtualStateCombined := false
		options, err := buildPermissionsEngineOptions(WithPermissionsEngineVirtualState(expVirtualState), WithPermissionsEngineVirtualStateViewCombined(expVirtualStateCombined))
		assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
		assert.Equal(options.enableVirtualState, expVirtualState, "wrong result\nenableVirtualState should be%s", spew.Sdump(expVirtualState))
		assert.Equal(options.virtualStateViewCombined, expVirtualStateCombined, "wrong result\nexpVirtualStateCombined should be%s", spew.Sdump(expVirtualStateCombined))
	}
	{
		expVirtualState := false
		expVirtualStateCombined := true
		options, err := buildPermissionsEngineOptions(WithPermissionsEngineVirtualState(expVirtualState), WithPermissionsEngineVirtualStateViewCombined(expVirtualStateCombined))
		assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
		assert.Equal(options.enableVirtualState, expVirtualState, "wrong result\nenableVirtualState should be%s", spew.Sdump(expVirtualState))
		assert.Equal(options.virtualStateViewCombined, expVirtualStateCombined, "wrong result\nexpVirtualStateCombined should be%s", spew.Sdump(expVirtualStateCombined))
	}
	{
		expVirtualState := true
		expVirtualStateCombined := true
		options, err := buildPermissionsEngineOptions(WithPermissionsEngineVirtualState(expVirtualState), WithPermissionsEngineVirtualStateViewCombined(expVirtualStateCombined))
		assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
		assert.Equal(options.enableVirtualState, expVirtualState, "wrong result\nenableVirtualState should be%s", spew.Sdump(expVirtualState))
		assert.Equal(options.virtualStateViewCombined, expVirtualStateCombined, "wrong result\nexpVirtualStateCombined should be%s", spew.Sdump(expVirtualStateCombined))
	}
	{
		expVirtualState := true
		expVirtualStateCombined := true
		_, err := buildPermissionsEngineOptions(WithPermissionsEngineVirtualState(expVirtualState), WithPermissionsEngineVirtualStateViewCombined(expVirtualStateCombined), func(options *PermissionsEngineOptions) error {
			return errors.New("Invalid Option")
		})
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
}
