// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzIntrnErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

var (
	// ErrAccessManagementUnsupportedBuilder is returned wether the builder is unsupported.
	ErrAccessManagementUnsupportedBuilder = errors.Join(errors.New("accessmanagement: unsupported builder"), authzIntrnErrors.UnsupportedFeatureBaseError)
	// ErrAccessManagementUnsupportedDataType is returned wether the data type is not supported.
	ErrAccessManagementUnsupportedDataType = errors.Join(errors.New("accessmanagement: unsupported data type"), authzIntrnErrors.UnsupportedDataTypeBaseError)
	// ErrAccessManagementInvalidDataType is returned wether the data type is invalid.
	ErrAccessManagementInvalidDataType = errors.Join(errors.New("accessmanagement: invalid data type"), authzIntrnErrors.InvalidDataTypeBaseError)
	// ErrAccessManagementUnsupportedSyntax is returned wether the string implement an unsupported syntax.
	ErrAccessManagementUnsupportedSyntax = errors.Join(errors.New("accessmanagement: unsupported syntax"), authzIntrnErrors.BadSyntaxBaseError)
	// ErrAccessManagementInvalidUUR is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidUUR = errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), authzIntrnErrors.BadSyntaxBaseError)
	// ErrAccessManagementInvalidAction is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidAction = errors.Join(errors.New("accessmanagement: invalid or unsupported action syntax"), authzIntrnErrors.BadSyntaxBaseError)
	// ErrAccessManagementUnsupportedVersion is returned wether required version is not supported.
	ErrAccessManagementUnsupportedVersion = errors.Join(errors.New("accessmanagement: unsupported version"), authzIntrnErrors.UnsupportedVersionBaseError)
	// ErrAccessManagementJSONSchemaValidation is returned wether the json schema validation failed.
	ErrAccessManagementJSONSchemaValidation = errors.Join(errors.New("accessmanagement: json schema validation failed"), authzIntrnErrors.JSONSchemaValidationBaseError)
)
