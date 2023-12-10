// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		jsonStr := `{"Syntax":"2022-08-08", "Type":"ACL"}`
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
		jsonStr := `{"Syntax":"autenticami1", "Type":"ACL", "Name": "12 3465 "}`
		_, err := engine.RegisterPolicy([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
}

func TestPermissionsEngineRegisterPolicy(t *testing.T) {
	engine := NewPermissionsEngine()
	jsonStr := `{"Syntax":"autenticami1", "Type":"ACL", "Name": "person-base-reader"}`
	_, _ = engine.RegisterPolicy([]byte(jsonStr))
	permState, err := engine.BuildPermissions(false)
	assert.Nil(t, err, "Err should be nil")
	assert.Equal(t, len(permState.permit), 0, "Permit list should be empty")
	assert.Equal(t, len(permState.forbid), 0, "Forbid list should be empty")
}
