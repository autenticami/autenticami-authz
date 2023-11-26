// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzIntErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

var (
	// ErrAccessManagementUnsupportedBuilder is returned wether the builder is unsupported.
	ErrAccessManagementUnsupportedBuilder = errors.Join(errors.New("accessmanagement: unsupported builder"), authzIntErrors.ErrBaseUnsupportedFeature)
	// ErrAccessManagementUnsupportedDataType is returned wether the data type is not supported.
	ErrAccessManagementUnsupportedDataType = errors.Join(errors.New("accessmanagement: unsupported data type"), authzIntErrors.ErrBaseUnsupportedDataType)
	// ErrAccessManagementInvalidDataType is returned wether the data type is invalid.
	ErrAccessManagementInvalidDataType = errors.Join(errors.New("accessmanagement: invalid data type"), authzIntErrors.ErrBaseInvalidDataType)
	// ErrAccessManagementUnsupportedSyntax is returned wether the string implement an unsupported syntax.
	ErrAccessManagementUnsupportedSyntax = errors.Join(errors.New("accessmanagement: unsupported syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccessManagementInvalidUUR is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidUUR = errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccessManagementInvalidAction is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidAction = errors.Join(errors.New("accessmanagement: invalid or unsupported action syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccessManagementUnsupportedVersion is returned wether required version is not supported.
	ErrAccessManagementUnsupportedVersion = errors.Join(errors.New("accessmanagement: unsupported version"), authzIntErrors.ErrBaseUnsupportedVersion)
	// ErrAccessManagementJSONSchemaValidation is returned wether the json schema validation failed.
	ErrAccessManagementJSONSchemaValidation = errors.Join(errors.New("accessmanagement: json schema validation failed"), authzIntErrors.ErrBaseJSONSchemaValidation)
)
