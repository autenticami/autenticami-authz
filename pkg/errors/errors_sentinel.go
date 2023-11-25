// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	cErrors "errors"

	iErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

const (
	// 1xxx
	codeGeneric = iErrors.ErrorCode(100)
	// 4xxx
	codeUnsupportedFeature = iErrors.ErrorCode(401)
	codeBadSyntax          = iErrors.ErrorCode(402)
	// 4xxx
	codeDataMarshaling       = iErrors.ErrorCode(501)
	codeDataUnmarshaling     = iErrors.ErrorCode(502)
	codeJSONSchemaValidation = iErrors.ErrorCode(520)
	codeUnsupportedDataType  = iErrors.ErrorCode(550)
	codeInvalidDataType      = iErrors.ErrorCode(551)
	codeUnsupportedVersion   = iErrors.ErrorCode(552)
)

var (
	// 1xx
	ErrCodeGeneric error = iErrors.NewError(codeGeneric)
	// 4xx
	ErrCodeUnsupportedFeature error = iErrors.NewError(codeUnsupportedFeature)
	ErrCodeBadSyntax          error = iErrors.NewError(codeBadSyntax)
	// 5xx
	ErrCodeDataMarshaling       error = iErrors.NewError(codeDataMarshaling)
	ErrCodeDataUnmarshaling     error = iErrors.NewError(codeDataUnmarshaling)
	ErrCodeJSONSchemaValidation error = iErrors.NewError(codeJSONSchemaValidation)
	ErrCodeUnsupportedDataType  error = iErrors.NewError(codeUnsupportedDataType)
	ErrCodeInvalidDataType      error = iErrors.NewError(codeInvalidDataType)
	ErrCodeUnsupportedVersion   error = iErrors.NewError(codeUnsupportedVersion)
)

var (
	// ErrJSONDataMarshaling is returned wether the json data cannot be marshaled.
	ErrJSONDataMarshaling = cErrors.Join(cErrors.New("core: json data cannot be marshaled"), ErrCodeDataMarshaling)
	// ErrJSONDataUnmarshaling is returned wether the json data cannot be unmarshaled.
	ErrJSONDataUnmarshaling = cErrors.Join(cErrors.New("core: json data cannot be unmarshaled"), ErrCodeDataUnmarshaling)
	// ErrJSONSchemaValidation is returned wether the json cannot validated with the json schema.
	ErrJSONSchemaValidation = cErrors.Join(cErrors.New("core: json schema validation failed"), ErrCodeJSONSchemaValidation)
)
