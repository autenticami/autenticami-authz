// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	cErrors "errors"

	authzIntrnErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

var (
	// ErrGeneric is returned wether the error is generic.
	ErrGeneric = cErrors.Join(cErrors.New("core: json data cannot be marshaled"), authzIntrnErrors.GenericBaseError)
	// ErrJSONDataMarshaling is returned wether the json data cannot be marshaled.
	ErrJSONDataMarshaling = cErrors.Join(cErrors.New("core: json data cannot be marshaled"), authzIntrnErrors.DataMarshalingBaseError)
	// ErrJSONDataUnmarshaling is returned wether the json data cannot be unmarshaled.
	ErrJSONDataUnmarshaling = cErrors.Join(cErrors.New("core: json data cannot be unmarshaled"), authzIntrnErrors.DataUnmarshalingBaseError)
	// ErrJSONSchemaValidation is returned wether the json cannot validated with the json schema.
	ErrJSONSchemaValidation = cErrors.Join(cErrors.New("core: json schema validation failed"), authzIntrnErrors.JSONSchemaValidationBaseError)
)
