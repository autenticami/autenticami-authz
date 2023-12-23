// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestCreateStringHash(t *testing.T) {
	assert := assert.New(t)
	exp := "03ac99ccafc04a3bad07b3a56ee2efec2b09f8ca765586c5aba7358927accc60"
	got := CreateStringHash("Autenticami")
	assert.Equal(exp, got, "wrong result\ngot should not be %s but %s", spew.Sdump(got), spew.Sdump(exp))
}
