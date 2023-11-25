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

func NewError(err ErrorCode) *Error {
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
