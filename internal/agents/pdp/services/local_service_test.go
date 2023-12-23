// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzIntAgentConfigs "github.com/autenticami/autenticami-authz/internal/agents/configs"
	authzIntPdpAgentConfigs "github.com/autenticami/autenticami-authz/internal/agents/pdp/configs"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/permissions"
	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
)

func TestBuildPermissionsState(t *testing.T) {
	type TestStruct struct {
		Name                string
		User                string
		Combined			bool
		LenOfForbid			int
		LenOfPermit			int
	}
	tests := []TestStruct{
		{
			"EMPTY-NOT-COMBINED",
			"",
			false,
			0,
			0,
		},
		{
			"USER-NOT-COMBINED",
			"uur:581616507495:default:autenticami:iam:user/nicola.gallo@nitroagility.com",
			false,
			1,
			9,
		},
		{
			"USER-COMBINED",
			"uur:581616507495:default:autenticami:iam:user/nicola.gallo@nitroagility.com",
			true,
			1,
			3,
		},
	}
	for _, test := range tests {
		t.Run(strings.ToUpper(test.Name), func(t *testing.T) {
			assert := assert.New(t)
			os.Setenv(authzIntAgentConfigs.EnvKeyAutenticamiAgentAppData, "./testdata/local-service/autenticami1")
			config, err := authzIntPdpAgentConfigs.NewPDPAgentConfig()
			assert.Nil(err, "wrong result\nerr shold be nil and not % s", spew.Sdump(err))
			service := NewPDPLocalService(config)
			_ = service.Setup()
			settings := []permissions.PermissionsEngineOption{
				permissions.WithPermissionsEngineVirtualState(true),
				permissions.WithPermissionsEngineVirtualStateViewCombined(test.Combined),
			}
			permState, err := service.GetPermissionsState(policies.UURString(test.User), settings[:]...)
			assert.Nil(err, "wrong result\nerr shold be nil and not %s", spew.Sdump(err))
			assert.NotNil(permState, "wrong result\npermState shold be not nil")

			forbidden, _ := permState.GetACLForbiddenPermissions()
			assert.Equal(test.LenOfForbid, len(forbidden), "wrong result\nforbidden shold be equale to 0")

			permit, _ := permState.GetACLPermittedPermissions()
			assert.Equal(test.LenOfPermit, len(permit), "wrong result\nforbidden shold be equale to 0")
		})
	}
}
