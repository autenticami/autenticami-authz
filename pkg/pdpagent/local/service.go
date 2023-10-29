// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	pkgAM "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPLocalService struct {
	config LocalConfig
	cache  map[string]interface{}
}
type papDoc struct {
	Items []map[string]interface{} `json:"items"`
}

func getBytes(key interface{}) ([]byte, error) {
    var buf bytes.Buffer
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})
    enc := gob.NewEncoder(&buf)
    err := enc.Encode(key)
    if err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

func loadCache(cache *map[string]interface{}, appFolder string, key string, targetKey string) error {
	files, err := os.ReadDir(appFolder)
	if err != nil {
		return errors.Join(ErrPDPAgentLocalInvalidAppData, err)
	}
	for _, file := range files {
		fileName := appFolder + file.Name()
		if filepath.Ext(fileName) != ".json" {
			continue
		}
		bArray, _ := os.ReadFile(fileName)
		var data papDoc
		err := json.Unmarshal(bArray, &data)
		if err != nil {
			return ErrPDPAgentLocalInvalidAppData
		}
		for _, item := range data.Items {
			key := item[key].(string)
			(*cache)[key] = item[targetKey]
		}
	}
	return nil
}

func (s PDPLocalService) Setup() error {
	var err error
	s.cache = make(map[string]interface{})
	err = loadCache(&s.cache, s.config.appData+"/autenticami1/identities/", "user_uur", "policies")
	if err != nil {
		return ErrPDPAgentLocalInvalidAppData
	}
	err = loadCache(&s.cache, s.config.appData+"/autenticami1/policies/", "policy_uur", "policy_payload")
	if err != nil {
		return ErrPDPAgentLocalInvalidAppData
	}
	return nil
}

func (s PDPLocalService) GetPermissionsState(identityUUR pkgAM.UURString) (*pkgAM.PermissionsState, error) {
	return nil, nil
}

func NewPDPLocalService(config LocalConfig) PDPLocalService {
	service := PDPLocalService{
		config: config,
	}
	return service
}
