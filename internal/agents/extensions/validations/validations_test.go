// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package validations

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestIsValidPathForValidPath(t *testing.T) {
	assert := assert.New(t)
	paths := []string { ".", "./", "~/data", "/home/data", "$HOME" }
	for _, path := range paths {
		isValid := IsValidPath(path)
		assert.True(isValid, "wrong result\npath %s should be valid", spew.Sdump(path))
	}
}

func TestIsValidPathForInvalidPath(t *testing.T) {
	assert := assert.New(t)
	paths := []string { "", " ", "a b C" }
	for _, path := range paths {
		isValid := IsValidPath(path)
		assert.False(isValid, "wrong result\npath %s should be not valid", spew.Sdump(path))
	}
}

func TestIsValidPortForValidPort(t *testing.T) {
	assert := assert.New(t)
	ports := []string { "1", "2", "65535" }
	for _, port := range ports {
		isValid := IsValidPort(port)
		assert.True(isValid, "wrong result\nport %s should be valid", spew.Sdump(port))
	}
}

func TestIsValidPortForInvalidPort(t *testing.T) {
	assert := assert.New(t)
	ports := []string { "", " ", "a b C", "-1", "0", "65536" }
	for _, port := range ports {
		isValid := IsValidPort(port)
		assert.False(isValid, "wrong result\nport %s should be not valid", spew.Sdump(port))
	}
}
