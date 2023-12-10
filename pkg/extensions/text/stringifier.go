// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func stringifyObj(obj any, exclude []string) string {
	if reflect.TypeOf(obj).Kind() == reflect.Array || reflect.TypeOf(obj).Kind() == reflect.Slice {
		if array, ok := obj.([]any); ok {
			arrayString := []string{}
			for _, item := range array {
				arrayString = append(arrayString, fmt.Sprintf("#%s", stringifyMap(item, exclude)))
			}
			arrayBuilder := strings.Builder{}
			sort.Strings(arrayString)
			for _, item := range arrayString {
				arrayBuilder.WriteString(item)
			}
			return arrayBuilder.String()
		}
	}
	return fmt.Sprintf("%v", obj)
}

func stringifyMap(obj any, exclude []string) string {
	if objMap, ok := obj.(map[string]any); ok {
		keys := make([]string, 0, len(objMap))
		for key := range objMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder := strings.Builder{}
		for _, key := range keys {
			if slices.Contains(exclude, key) {
				continue
			}
			value := (objMap)[key]
			builder.WriteString(fmt.Sprintf("#%s#%s", key, stringifyMap(value, exclude)))
		}
		return builder.String()
	}
	return stringifyObj(obj, exclude)
}

func Stringify(obj any, exclude []string) (string, error) {
	var objMap map[string]any
	dataObj, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(dataObj, &objMap)
	if err != nil {
		return "", err
	}
	return stringifyMap(objMap, exclude), nil
}
