// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCodes(t *testing.T) {
	assert := assert.New(t)
	{
		err := errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), ErrBaseGeneric)
		assert.True(errors.Is(err, ErrBaseGeneric), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
		assert.False(errors.Is(err, ErrBaseUnsupportedFeature), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
		assert.Equal("core: [code 100] generic error", string(ErrBaseGeneric.Error()), "wrong result\nErrors should be equal")
	}
	{
		err := errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), ErrBaseBadSyntax)
		assert.True(errors.Is(err, ErrBaseBadSyntax), "wrong result\nError Join should include type ErrCodeBadSyntax")

		var errType *baseError
		assert.True(errors.As(err, &errType), "wrong result\nError Join should be able to extract an error as ErrCodeBadSyntax")
		assert.True(errors.Is(errType, ErrBaseBadSyntax), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
	}
	{
		var errType *baseError
		assert.True(errors.As(ErrBaseBadSyntax, &errType), "wrong result\nErrCodeBadSyntax should be able to extract an error as ErrCodeBadSyntax")
		assert.Equal(errType.GetCode(), 402, "wrong result\n Wrong error code")
		assert.Equal(errType.GetMessage(), "bad syntax", "wrong result\nWrong error message")
	}
	{
		assert.True(errors.Is(ErrBaseGeneric, ErrBaseGeneric), "wrong result\nErrors shold be the same")
		assert.False(errors.Is(ErrBaseGeneric, ErrBaseUnsupportedFeature), "wrong result\nErrors sholdn't be the same")
		assert.False(errors.Is(ErrBaseGeneric, errors.New("Sample errore")), "wrong result\nErrors sholdn't be the same")
	}
	{
		assert.True(errors.Is(errorCode(100), errorCode(100)), "wrong result\nErrors shold be the same")
		assert.False(errors.Is(errorCode(100), errorCode(401)), "wrong result\nErrors sholdn't be the same")
		assert.False(errors.Is(errorCode(100), errors.New("Sample errore")), "wrong result\nErrors sholdn't be the same")
	}
	{
		assert.Equal(unknownText, errorCode(0).Message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(newBaseError(errorCode(0))), "wrong result\nErrors shold be the same")

		assert.Equal(unknownText, errorCode(9999).Message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(newBaseError(errorCode(9999))), "wrong result\nErrors shold be the same")
	}
}
