// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"errors"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	"github.com/autenticami/autenticami-authz/internal/agents/configs"
	authzIntAgentErrors "github.com/autenticami/autenticami-authz/internal/agents/errors"

)

func TestPDPAgentConfig(t *testing.T) {
	assert := assert.New(t)
	{
		_, err := NewPDPAgentConfig()
		assert.Nil(err, "wrong result\nerror shold be nil and not %s", spew.Sdump(err))
	}
	{
		os.Setenv(configs.EnvKeyAutenticamiAgentType, "TEST")
		agent, err := NewPDPAgentConfig()
		assert.True(errors.Is(err, authzIntAgentErrors.ErrAgentInvalidType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAgentInvalidType", spew.Sdump(err))
		assert.Nil(agent, "wrong result\nagent shold be nil and not")
	}
	{
		os.Setenv(configs.EnvKeyAutenticamiAgentPort, "0 1 2 3 4 5 6")
		agent, err := NewPDPAgentConfig()
		assert.True(errors.Is(err, authzIntAgentErrors.ErrAgentInvalidPort), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAgentInvalidType", spew.Sdump(err))
		assert.Nil(agent, "wrong result\nagent shold be nil and not")
	}
	{
		os.Setenv(configs.EnvKeyAutenticamiAgentAppData, "0 1 2 3 4 5 6")
		agent, err := NewPDPAgentConfig()
		assert.True(errors.Is(err, authzIntAgentErrors.ErrAgentInvalidAppData), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAgentInvalidType", spew.Sdump(err))
		assert.Nil(agent, "wrong result\nagent shold be nil and not")
	}
}
