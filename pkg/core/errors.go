// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"

	pkgiCore "github.com/autenticami/autenticami-authz/pkg/internal/core"
)

var (
	// ErrJSONDataMarshaling is returned wether the json data cannot be marshaled.
	ErrJSONDataMarshaling = errors.Join(errors.New("core: json data cannot be marshaled"), pkgiCore.ErrCodeDataMarshaling)
	// ErrJSONDataUnmarshaling is returned wether the json data cannot be unmarshaled.
	ErrJSONDataUnmarshaling = errors.Join(errors.New("core: json data cannot be unmarshaled"), pkgiCore.ErrCodeDataUnmarshaling)
	// ErrJSONSchemaValidation is returned wether the json cannot validated with the json schema.
	ErrJSONSchemaValidation = errors.Join(errors.New("core: json schema validation failed"), pkgiCore.ErrCodeJSONSchemaValidation)
)
