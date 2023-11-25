// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/autenticami/autenticami-authz/internal/agents/pdp/configs"
	iErrors "github.com/autenticami/autenticami-authz/internal/agents/pdp/errors"
	am "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
)

type PDPLocalService struct {
	config *configs.PDPAgentConfig
	cache  map[string]interface{}
}

type papDoc struct {
	Items []map[string]interface{} `json:"items"`
}

func loadCache(cache *map[string]interface{}, appFolder string, key string, targetKey string, encode bool) error {
	files, err := os.ReadDir(appFolder)
	if err != nil {
		return errors.Join(iErrors.ErrPDPAgentLocalInvalidAppData, err)
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
			return errors.Join(iErrors.ErrPDPAgentLocalInvalidAppData, err)
		}
		for _, item := range data.Items {
			key := item[key].(string)
			if !encode {
				(*cache)[key] = item[targetKey]
			} else {
				bytes, err := json.Marshal(item[targetKey])
				if err != nil {
					return errors.Join(iErrors.ErrPDPAgentLocalInvalidAppData, err)
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
	err = loadCache(&s.cache, s.config.GetAgentAppData()+"/autenticami1/identities/", "user_uur", "policies", false)
	if err != nil {
		return iErrors.ErrPDPAgentLocalInvalidAppData
	}
	err = loadCache(&s.cache, s.config.GetAgentAppData()+"/autenticami1/policies/", "policy_uur", "policy_payload", true)
	if err != nil {
		return iErrors.ErrPDPAgentLocalInvalidAppData
	}
	return nil
}

func (s *PDPLocalService) GetPermissionsState(identityUUR am.UURString) (*am.PermissionsState, error) {
	engine, err := am.NewPermissionsEngine()
	if err != nil {
		return nil, err
	}
	var permissionState *am.PermissionsState
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

func NewPDPLocalService(config *configs.PDPAgentConfig) *PDPLocalService {
	service := PDPLocalService{
		config: config,
	}
	return &service
}
