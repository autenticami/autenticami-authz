// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package validations

import (
	"os"
	"strconv"
)

func IsValidPath(path string) bool {
    _, err := os.Stat(path)
    if err == nil { return true }
    return !os.IsNotExist(err)
}

func IsValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}
