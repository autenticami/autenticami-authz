// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"strconv"
)

const (
	UnknownText = "unknown"
)

type errorCode int

type Error struct {
	err errorCode
}

const (
	// 1xxx
	codeGeneric = errorCode(100)
	// 4xxx
	codeUnsupportedFeature = errorCode(401)
	codeBadSyntax          = errorCode(402)
	// 4xxx
	codeDataMarshaling       = errorCode(501)
	codeDataUnmarshaling     = errorCode(502)
	codeJSONSchemaValidation = errorCode(520)
	codeUnsupportedDataType  = errorCode(550)
	codeInvalidDataType      = errorCode(551)
	codeUnsupportedVersion   = errorCode(552)
)

var (
	// 1xx
	ErrCodeGeneric error = &Error{codeGeneric}
	// 4xx
	ErrCodeUnsupportedFeature error = &Error{codeUnsupportedFeature}
	ErrCodeBadSyntax          error = &Error{codeBadSyntax}
	// 5xx
	ErrCodeDataMarshaling       error = &Error{codeDataMarshaling}
	ErrCodeDataUnmarshaling     error = &Error{codeDataUnmarshaling}
	ErrCodeJSONSchemaValidation error = &Error{codeJSONSchemaValidation}
	ErrCodeUnsupportedDataType  error = &Error{codeUnsupportedDataType}
	ErrCodeInvalidDataType      error = &Error{codeInvalidDataType}
	ErrCodeUnsupportedVersion   error = &Error{codeUnsupportedVersion}
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

func (e errorCode) Error() string {
	message := e.message()
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

func (e errorCode) message() string {
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
	return e.err.message()
}
