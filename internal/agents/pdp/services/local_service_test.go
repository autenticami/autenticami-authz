// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	authzIntAgentConfigs "github.com/autenticami/autenticami-authz/internal/agents/configs"
	authzIntPdpAgentConfigs "github.com/autenticami/autenticami-authz/internal/agents/pdp/configs"
)

func TestPDPAgentConfig(t *testing.T) {
	assert := assert.New(t)
	os.Setenv(authzIntAgentConfigs.EnvKeyAutenticamiAgentAppData, "./testdata/local-service/autenticami1")
	config, err := authzIntPdpAgentConfigs.NewPDPAgentConfig()
	assert.Nil(err, "wrong result\nerr shold be nil and not % s", spew.Sdump(err))
	service := NewPDPLocalService(config)
	settings := []permissions.PermissionsEngineOption{
		permissions.WithPermissionsEngineVirtualState(true),
		permissions.WithPermissionsEngineVirtualStateViewCombined(true),
	}
	permState, err := service.GetPermissionsState("", settings[:]...)
	assert.Nil(err, "wrong result\nerr shold be nil and not %s", spew.Sdump(err))
	assert.NotNil(permState, "wrong result\npermState shold be not nil")
}
