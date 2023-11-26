// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"fmt"
	"strconv"
)

const (
	UnknownText = "unknown"
)

type ErrorCode int

type Error struct {
	err ErrorCode
}

func newError(err ErrorCode) *Error {
	return &Error{err}
}

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
	errorCodeGeneric = ErrorCode(100)
	// 4xxx
	errorCodeUnsupportedFeature = ErrorCode(401)
	errorCodeBadSyntax          = ErrorCode(402)
	// 4xxx
	errorCodeDataMarshaling       = ErrorCode(501)
	errorCodeDataUnmarshaling     = ErrorCode(502)
	errorCodeJSONSchemaValidation = ErrorCode(520)
	errorCodeUnsupportedDataType  = ErrorCode(550)
	errorCodeInvalidDataType      = ErrorCode(551)
	errorCodeUnsupportedVersion   = ErrorCode(552)
)

var (
	// 1xx
	ErrCodeGeneric error = newError(errorCodeGeneric)
	// 4xx
	ErrCodeUnsupportedFeature error = newError(errorCodeUnsupportedFeature)
	ErrCodeBadSyntax          error = newError(errorCodeBadSyntax)
	// 5xx
	ErrCodeDataMarshaling       error = newError(errorCodeDataMarshaling)
	ErrCodeDataUnmarshaling     error = newError(errorCodeDataUnmarshaling)
	ErrCodeJSONSchemaValidation error = newError(errorCodeJSONSchemaValidation)
	ErrCodeUnsupportedDataType  error = newError(errorCodeUnsupportedDataType)
	ErrCodeInvalidDataType      error = newError(errorCodeInvalidDataType)
	ErrCodeUnsupportedVersion   error = newError(errorCodeUnsupportedVersion)
)

func (e ErrorCode) Error() string {
	message := e.Message()
	if 0 <= int(e) && int(e) < len(errorCodes) {
		s := errorCodes[e]
		if s != "" {
			return fmt.Sprintf("[code %s] %s", strconv.FormatInt(int64(e), 10), message)
		}
	}
	return message
}

func (e ErrorCode) Is(tgt error) bool {
	target, ok := tgt.(ErrorCode)
	if !ok {
		return false
	}
	return e == target
}

func (e ErrorCode) Message() string {
	var message string
	if 0 <= int(e) && int(e) < len(errorCodes) {
		message = errorCodes[e]
	}
	if message == "" {
		message = UnknownText
	}
	return message
}

func (e *Error) Error() string {
	return fmt.Sprintf("core: %s", e.err)
}

func (e *Error) Is(tgt error) bool {
	target, ok := tgt.(*Error)
	if !ok {
		return false
	}
	return e.err == target.err
}

func (e *Error) GetCode() int {
	return int(e.err)
}

func (e *Error) GetMessage() string {
	return e.err.Message()
}
