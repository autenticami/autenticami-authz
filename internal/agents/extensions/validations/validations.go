// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package validations

import (
	"path/filepath"
	"strconv"
)

func IsValidPath(path string) bool {
	if path == "." || path == "./" {
		return true
	}
	cleanPath := filepath.Clean(path)
	return cleanPath != "." && cleanPath != ""
}

func IsValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}
