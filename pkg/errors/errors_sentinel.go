// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	cErrors "errors"

	iErrors "github.com/autenticami/autenticami-authz/pkg/internal/errors"
)

var (
	// ErrGeneric is returned wether the error is generic.
	ErrGeneric = cErrors.Join(cErrors.New("core: json data cannot be marshaled"), iErrors.GenericBaseError)
	// ErrJSONDataMarshaling is returned wether the json data cannot be marshaled.
	ErrJSONDataMarshaling = cErrors.Join(cErrors.New("core: json data cannot be marshaled"), iErrors.DataMarshalingBaseError)
	// ErrJSONDataUnmarshaling is returned wether the json data cannot be unmarshaled.
	ErrJSONDataUnmarshaling = cErrors.Join(cErrors.New("core: json data cannot be unmarshaled"), iErrors.DataUnmarshalingBaseError)
	// ErrJSONSchemaValidation is returned wether the json cannot validated with the json schema.
	ErrJSONSchemaValidation = cErrors.Join(cErrors.New("core: json schema validation failed"), iErrors.JSONSchemaValidationBaseError)
)
