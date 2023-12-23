// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package environments

import (
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	assert := assert.New(t)
	{
		exp := "DEV"
		got := GetEnv("ENV1", exp)
		assert.Equal(exp, got, "wrong result\nexp % and got %s should be equale", spew.Sdump(exp), spew.Sdump(got))
	}
	{
		exp := "DEV"
		os.Setenv("ENV1", exp)
		got := GetEnv("ENV1", "BINGO")
		assert.Equal(exp, got, "wrong result\nexp % and got %s should be equale", spew.Sdump(exp), spew.Sdump(got))
	}
}
