// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"

	authzIntErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

var (
	// ErrAccesscontrolUnsupportedBuilder is returned wether the builder is unsupported.
	ErrAccesscontrolUnsupportedBuilder = errors.Join(errors.New("accesscontrol: unsupported builder"), authzIntErrors.ErrBaseUnsupportedFeature)
	// ErrAccesscontrolUnsupportedDataType is returned wether the data type is not supported.
	ErrAccesscontrolUnsupportedDataType = errors.Join(errors.New("accesscontrol: unsupported data type"), authzIntErrors.ErrBaseUnsupportedDataType)
	// ErrAccesscontrolInvalidDataType is returned wether the data type is invalid.
	ErrAccesscontrolInvalidDataType = errors.Join(errors.New("accesscontrol: invalid data type"), authzIntErrors.ErrBaseInvalidDataType)
	// ErrAccesscontrolUnsupportedSyntax is returned wether the string implement an unsupported syntax.
	ErrAccesscontrolUnsupportedSyntax = errors.Join(errors.New("accesscontrol: unsupported syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccesscontrolInvalidUUR is returned wether the action string is invalid or unsupported.
	ErrAccesscontrolInvalidUUR = errors.Join(errors.New("accesscontrol: invalid or unsupported uur syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccesscontrolInvalidAction is returned wether the action string is invalid or unsupported.
	ErrAccesscontrolInvalidAction = errors.Join(errors.New("accesscontrol: invalid or unsupported action syntax"), authzIntErrors.ErrBaseBadSyntax)
	// ErrAccesscontrolUnsupportedVersion is returned wether required version is not supported.
	ErrAccesscontrolUnsupportedVersion = errors.Join(errors.New("accesscontrol: unsupported version"), authzIntErrors.ErrBaseUnsupportedVersion)
	// ErrAccesscontrolJSONSchemaValidation is returned wether the json schema validation failed.
	ErrAccesscontrolJSONSchemaValidation = errors.Join(errors.New("accesscontrol: json schema validation failed"), authzIntErrors.ErrBaseJSONSchemaValidation)
)
