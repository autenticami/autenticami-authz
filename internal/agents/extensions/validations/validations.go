// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package validations

import (
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
)

func IsValidPath(path string) bool {
	if path == "." || path == "./" {
		return true
	}
	cleanPath := filepath.Clean(path)
	var regexString string
	switch runtime.GOOS {
	case "windows":
		regexString = `^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$`
	default:
		regexString = `^(~/(?:[^/]+(/[^/]+)*)?|/([^/]+(/[^/]+)*)?)$`
	}
	regex := regexp.MustCompile(regexString)
	return regex.MatchString(cleanPath)
}

func IsValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}
