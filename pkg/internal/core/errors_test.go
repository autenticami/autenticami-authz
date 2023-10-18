// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCodes(t *testing.T) {
	assert := assert.New(t)
	{
		err := errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), ErrCodeGeneric)
		assert.True(errors.Is(err, ErrCodeGeneric), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
		assert.False(errors.Is(err, ErrCodeUnsupportedFeature), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
		assert.Equal("core: [code 100] generic error", string(ErrCodeGeneric.Error()), "wrong result\nErrors should be equal")
	}
	{
		err := errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), ErrCodeBadSyntax)
		assert.True(errors.Is(err, ErrCodeBadSyntax), "wrong result\nError Join should include type ErrCodeBadSyntax")

		var errType *Error
		assert.True(errors.As(err, &errType), "wrong result\nError Join should be able to extract an error as ErrCodeBadSyntax")
		assert.True(errors.Is(errType, ErrCodeBadSyntax), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
	}
	{
		var errType *Error
		assert.True(errors.As(ErrCodeBadSyntax, &errType), "wrong result\nErrCodeBadSyntax should be able to extract an error as ErrCodeBadSyntax")
		assert.Equal(errType.GetCode(), 402, "wrong result\n Wrong error code")
		assert.Equal(errType.GetMessage(), "bad syntax", "wrong result\nWrong error message")
	}
	{
		assert.True(errors.Is(ErrCodeGeneric, ErrCodeGeneric), "wrong result\nErrors shold be the same")
		assert.False(errors.Is(ErrCodeGeneric, ErrCodeUnsupportedFeature), "wrong result\nErrors sholdn't be the same")
		assert.False(errors.Is(ErrCodeGeneric, errors.New("Sample errore")), "wrong result\nErrors sholdn't be the same")
	}
	{
		assert.True(errors.Is(errorCode(100), errorCode(100)), "wrong result\nErrors shold be the same")
		assert.False(errors.Is(errorCode(100), errorCode(401)), "wrong result\nErrors sholdn't be the same")
		assert.False(errors.Is(errorCode(100), errors.New("Sample errore")), "wrong result\nErrors sholdn't be the same")
	}
	{
		assert.Equal(UnknownText, errorCode(0).message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(&Error{errorCode(0)}), "wrong result\nErrors shold be the same")

		assert.Equal(UnknownText, errorCode(9999).message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(&Error{errorCode(9999)}), "wrong result\nErrors shold be the same")
	}
}
