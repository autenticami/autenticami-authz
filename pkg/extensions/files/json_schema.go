// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"errors"

	"github.com/xeipuuv/gojsonschema"

	authzErrors "github.com/autenticami/autenticami-authz/pkg/errors"
)

func IsValidJSON(jsonSchme []byte, json []byte) (bool, error) {
	schemaLoader := gojsonschema.NewBytesLoader(jsonSchme)
	documentLoader := gojsonschema.NewBytesLoader(json)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, errors.Join(authzErrors.ErrJSONSchemaValidation, err)
	}
	if result.Valid() {
		return true, nil
	} else {
		return false, nil
	}
}
