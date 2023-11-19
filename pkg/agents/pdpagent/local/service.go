// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	pkgPdp "github.com/autenticami/autenticami-authz/pkg/agents/pdpagent"
	pkgAM "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPLocalService struct {
	config *pkgPdp.PDPAgentConfig
	cache  map[string]interface{}
}

type papDoc struct {
	Items []map[string]interface{} `json:"items"`
}

func loadCache(cache *map[string]interface{}, appFolder string, key string, targetKey string, encode bool) error {
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
			return errors.Join(ErrPDPAgentLocalInvalidAppData, err)
		}
		for _, item := range data.Items {
			key := item[key].(string)
			if !encode {
				(*cache)[key] = item[targetKey]
			} else {
				bytes, err := json.Marshal(item[targetKey])
				if err != nil {
					return errors.Join(ErrPDPAgentLocalInvalidAppData, err)
				}
				(*cache)[key] = bytes
			}
		}
	}
	return nil
}

func (s *PDPLocalService) Setup() error {
	var err error
	s.cache = make(map[string]interface{})
	err = loadCache(&s.cache, s.config.GetAgentAppData() + "/autenticami1/identities/", "user_uur", "policies", false)
	if err != nil {
		return ErrPDPAgentLocalInvalidAppData
	}
	err = loadCache(&s.cache, s.config.GetAgentAppData() + "/autenticami1/policies/", "policy_uur", "policy_payload", true)
	if err != nil {
		return ErrPDPAgentLocalInvalidAppData
	}
	return nil
}

func (s *PDPLocalService) GetPermissionsState(identityUUR pkgAM.UURString) (*pkgAM.PermissionsState, error) {
	engine, err := pkgAM.NewPermissionsEngine()
	if err != nil {
		return nil, err
	}
	var permissionState *pkgAM.PermissionsState
	policies := s.cache[string(identityUUR)]
	if policies != nil {
		for _, policy := range policies.([]interface{}) {
			permissionState, err = engine.BuildPermissions(s.cache[policy.(string)].([]byte))
		}
	}
	if err != nil {
		return nil, err
	}
	return permissionState, nil
}

func NewPDPLocalService(config *pkgPdp.PDPAgentConfig) *PDPLocalService {
	service := PDPLocalService{
		config: config,
	}
	return &service
}
