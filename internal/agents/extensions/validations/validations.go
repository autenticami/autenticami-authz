// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package validations

import (
	"path/filepath"
	"strconv"
	"strings"
)

func IsValidPath(path string) bool {
	if len(strings.ReplaceAll(path, " ", "")) == 0 {
		return false
	}
	if path == "." || path == "./" {
		return true
	}
	cleanPath := filepath.Clean(path)
	cleanPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return false
	}
	isAbs := filepath.IsAbs(cleanPath)
	return isAbs
}

func IsValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}
