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
		_, err := engine.BuildPermissions(nil)
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		_, err := engine.BuildPermissions([]byte{})
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"2022-08-08", "Type":"ACL"}`
		_, err := engine.BuildPermissions([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"autenticami1", "Type":"ABC"}`
		_, err := engine.BuildPermissions([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
	{
		engine := NewPermissionsEngine()
		jsonStr := `{"Syntax":"autenticami1", "Type":"ACL", "Name": "12 3465 "}`
		_, err := engine.BuildPermissions([]byte(jsonStr))
		assert.NotNil(t, err, "Err shouldn't be nil")
	}
}

func TestPermissionsEngineBuildPermissions(t *testing.T) {
	engine := NewPermissionsEngine()
	jsonStr := `{"Syntax":"autenticami1", "Type":"ACL", "Name": "person-base-reader"}`
	permissionsState, err := engine.BuildPermissions([]byte(jsonStr))
	assert.Nil(t, err, "Err should be nil")
	assert.Equal(t, len(permissionsState.permit), 0, "Permit list should be empty")
	assert.Equal(t, len(permissionsState.forbid), 0, "Forbid list should be empty")
}
