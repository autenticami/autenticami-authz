// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"path/filepath"
	"strconv"
)

func IsValidPath(path string) bool {
	cleanPath := filepath.Clean(path)
	return cleanPath == path
}

func IsValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}
