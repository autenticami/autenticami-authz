// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	iErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

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

		var errType *iErrors.Error
		assert.True(errors.As(err, &errType), "wrong result\nError Join should be able to extract an error as ErrCodeBadSyntax")
		assert.True(errors.Is(errType, ErrCodeBadSyntax), "wrong result\nErrCodeGeneric shold be equal to error Codes creted with the same number")
	}
	{
		var errType *iErrors.Error
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
		assert.True(errors.Is(iErrors.ErrorCode(100), iErrors.ErrorCode(100)), "wrong result\nErrors shold be the same")
		assert.False(errors.Is(iErrors.ErrorCode(100), iErrors.ErrorCode(401)), "wrong result\nErrors sholdn't be the same")
		assert.False(errors.Is(iErrors.ErrorCode(100), errors.New("Sample errore")), "wrong result\nErrors sholdn't be the same")
	}
	{
		assert.Equal(iErrors.UnknownText, iErrors.ErrorCode(0).Message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(&iErrors.Error{iErrors.ErrorCode(0)}), "wrong result\nErrors shold be the same")

		assert.Equal(iErrors.UnknownText, iErrors.ErrorCode(9999).Message(), "wrong result\nErrors shold be the same")
		assert.Equal("core: unknown", fmt.Sprint(&iErrors.Error{iErrors.ErrorCode(9999)}), "wrong result\nErrors shold be the same")
	}
}
