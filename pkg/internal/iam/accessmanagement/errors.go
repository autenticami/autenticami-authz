// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	"errors"

	pkgi_core "github.com/autenticami/autenticami-authz/pkg/internal/core"
)

var (
	// ErrAccessManagementUnsupportedBuilder is returned wether the builder is unsupported.
	ErrAccessManagementUnsupportedBuilder = errors.Join(errors.New("accessmanagement: unsupported builder"), pkgi_core.ErrCodeUnsupportedFeature)
	// ErrAccessManagementUnsupportedDataType is returned wether the data type is not supported.
	ErrAccessManagementUnsupportedDataType = errors.Join(errors.New("accessmanagement: unsupported data type"), pkgi_core.ErrCodeUnsupportedDataType)
	// ErrAccessManagementInvalidDataType is returned wether the data type is invalid.
	ErrAccessManagementInvalidDataType = errors.Join(errors.New("accessmanagement: invalid data type"), pkgi_core.ErrCodeInvalidDataType)
	// ErrAccessManagementUnsupportedSyntax is returned wether the string implement an unsupported syntax.
	ErrAccessManagementUnsupportedSyntax = errors.Join(errors.New("accessmanagement: unsupported syntax"), pkgi_core.ErrCodeBadSyntax)
	// ErrAccessManagementInvalidUUR is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidUUR = errors.Join(errors.New("accessmanagement: invalid or unsupported uur syntax"), pkgi_core.ErrCodeBadSyntax)
	// ErrAccessManagementInvalidAction is returned wether the action string is invalid or unsupported.
	ErrAccessManagementInvalidAction = errors.Join(errors.New("accessmanagement: invalid or unsupported action syntax"), pkgi_core.ErrCodeBadSyntax)
	// ErrAccessManagementUnsupportedVersion is returned wether required version is not supported.
	ErrAccessManagementUnsupportedVersion = errors.Join(errors.New("accessmanagement: unsupported version"), pkgi_core.ErrCodeUnsupportedVersion)
	// ErrAccessManagementJSONSchemaValidation is returned wether the json schema validation failed.
	ErrAccessManagementJSONSchemaValidation = errors.Join(errors.New("accessmanagement: json schema validation failed"), pkgi_core.ErrCodeJSONSchemaValidation)
)
