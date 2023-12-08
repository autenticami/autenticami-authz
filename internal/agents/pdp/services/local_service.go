// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/autenticami/autenticami-authz/internal/agents/pdp/configs"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"

	authzIntAgentErrors "github.com/autenticami/autenticami-authz/internal/agents/errors"
)

type PDPLocalService struct {
	config *configs.PDPAgentConfig
	cache  map[string]any
}

type papDoc struct {
	Items []map[string]any `json:"items"`
}

func loadCache(cache *map[string]any, appFolder string, key string, targetKey string, encode bool) error {
	files, err := os.ReadDir(appFolder)
	if err != nil {
		return errors.Join(authzIntAgentErrors.ErrAgentInvalidAppData, err)
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
			return errors.Join(authzIntAgentErrors.ErrAgentInvalidAppData, err)
		}
		for _, item := range data.Items {
			key := item[key].(string)
			if !encode {
				(*cache)[key] = item[targetKey]
			} else {
				bytes, err := json.Marshal(item[targetKey])
				if err != nil {
					return errors.Join(authzIntAgentErrors.ErrAgentInvalidAppData, err)
				}
				(*cache)[key] = bytes
			}
		}
	}
	return nil
}

func (s *PDPLocalService) Setup() error {
	var err error
	s.cache = make(map[string]any)
	err = loadCache(&s.cache, s.config.GetAgentAppData()+"/autenticami1/identities/", "user_uur", "policies", false)
	if err != nil {
		return authzIntAgentErrors.ErrAgentInvalidAppData
	}
	err = loadCache(&s.cache, s.config.GetAgentAppData()+"/autenticami1/policies/", "policy_uur", "policy_payload", true)
	if err != nil {
		return authzIntAgentErrors.ErrAgentInvalidAppData
	}
	return nil
}

func (s *PDPLocalService) GetPermissionsState(identityUUR policies.UURString) (*permissions.PermissionsState, error) {
	engine, err := permissions.NewPermissionsEngine()
	if err != nil {
		return nil, err
	}
	var permissionState *permissions.PermissionsState
	policies := s.cache[string(identityUUR)]
	if policies != nil {
		for _, policy := range policies.([]any) {
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
