// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"fmt"
	"strconv"
)

const (
	unknownText = "unknown"
)

var errorCodes = [...]string{
	// 1xx generic errors
	100: "generic error",
	// 4xx bad syntax/implementation
	401: "unsupported feature",
	402: "bad syntax",
	// 5xx bad data
	501: "data cannot be marshaled",
	502: "data cannot be unmarshaled",
	520: "json schema validation failed",
	550: "unsupported datatype",
	551: "invalid datatype",
	552: "unsupported version",
}

const (
	// 1xxx
	errorCodeGeneric = errorCode(100)
	// 4xxx
	errorCodeUnsupportedFeature = errorCode(401)
	errorCodeBadSyntax          = errorCode(402)
	// 4xxx
	errorCodeDataMarshaling       = errorCode(501)
	errorCodeDataUnmarshaling     = errorCode(502)
	errorCodeJSONSchemaValidation = errorCode(520)
	errorCodeUnsupportedDataType  = errorCode(550)
	errorCodeInvalidDataType      = errorCode(551)
	errorCodeUnsupportedVersion   = errorCode(552)
)

var (
	// 1xx
	ErrBaseGeneric error = newBaseError(errorCodeGeneric)
	// 4xx
	ErrBaseUnsupportedFeature error = newBaseError(errorCodeUnsupportedFeature)
	ErrBaseBadSyntax          error = newBaseError(errorCodeBadSyntax)
	// 5xx
	ErrBaseDataMarshaling       error = newBaseError(errorCodeDataMarshaling)
	ErrBaseDataUnmarshaling     error = newBaseError(errorCodeDataUnmarshaling)
	ErrBaseJSONSchemaValidation error = newBaseError(errorCodeJSONSchemaValidation)
	ErrBaseUnsupportedDataType  error = newBaseError(errorCodeUnsupportedDataType)
	ErrBaseInvalidDataType      error = newBaseError(errorCodeInvalidDataType)
	ErrBaseUnsupportedVersion   error = newBaseError(errorCodeUnsupportedVersion)
)

type errorCode int

type baseError struct {
	err errorCode
}

func newBaseError(err errorCode) *baseError {
	return &baseError{err}
}

func (e errorCode) Error() string {
	message := e.Message()
	if 0 <= int(e) && int(e) < len(errorCodes) {
		s := errorCodes[e]
		if s != "" {
			return fmt.Sprintf("[code %s] %s", strconv.FormatInt(int64(e), 10), message)
		}
	}
	return message
}

func (e errorCode) Is(tgt error) bool {
	target, ok := tgt.(errorCode)
	if !ok {
		return false
	}
	return e == target
}

func (e errorCode) Message() string {
	var message string
	if 0 <= int(e) && int(e) < len(errorCodes) {
		message = errorCodes[e]
	}
	if message == "" {
		message = unknownText
	}
	return message
}

func (e *baseError) Error() string {
	return fmt.Sprintf("core: %s", e.err)
}

func (e *baseError) Is(tgt error) bool {
	target, ok := tgt.(*baseError)
	if !ok {
		return false
	}
	return e.err == target.err
}

func (e *baseError) GetCode() int {
	return int(e.err)
}

func (e *baseError) GetMessage() string {
	return e.err.Message()
}
