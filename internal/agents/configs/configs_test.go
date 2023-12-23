// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	"errors"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	authzIntAgentErrors "github.com/autenticami/autenticami-authz/internal/agents/errors"
)

func TestAgentConfig(t *testing.T) {
	assert := assert.New(t)
	{
		agentType := ""
		agent, err := NewAgentConfig(agentType)
		assert.True(errors.Is(err, authzIntAgentErrors.ErrAgentInvalidType), "wrong result\ngot: %sshould be of type authzAMErrors. ErrAgentInvalidType", spew.Sdump(err))
		assert.Nil(agent, "wrong result\nagent shold be nil and not")
	}
	{
		agentType := "PDP-AGENT"
		agent, err := NewAgentConfig(agentType)
		assert.Nil(err, "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
		assert.True(agent.IsLocalEnv(), "wrong result\nIsLocalEnv should be equal to%s", spew.Sdump(true))
		exp	:= agentType
		assert.Equal(exp, agent.GetAgentType(), "wrong result\nGetAgentType should be equal to%s", spew.Sdump(exp))
		exp	= "./"
		assert.Equal(exp, agent.GetAgentAppData(), "wrong result\nGetAgentAppData should be equal to%s", spew.Sdump(exp))
		exp	= "9090"
		assert.Equal(exp, agent.GetAgentPort(), "wrong result\nGetAgentPortshould be equal to%s", spew.Sdump(exp))
	}
	{
		environment := "DEV"
		os.Setenv(EnvKeyAutenticamiEnvironment, environment)
		appData := "~/appdata"
		os.Setenv(EnvKeyAutenticamiAgentAppData, appData)
		port := "9093"
		os.Setenv(EnvKeyAutenticamiAgentPort, port)
		agentType := "PDP-AGENT"
 		agent, err := NewAgentConfig(agentType)
		assert.Nil(err, "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
		assert.False(agent.IsLocalEnv(), "wrong result\nnIsLocalEnv should be not true", spew.Sdump(true))
		exp	:= agentType
		assert.Equal(exp, agent.GetAgentType(), "wrong result\nGetAgentType should be equal to%s", spew.Sdump(exp))
		exp	= appData
		assert.Equal(exp, agent.GetAgentAppData(), "wrong result\nGetAgentAppData should be equal to%s", spew.Sdump(exp))
		exp	= port
		assert.Equal(exp, agent.GetAgentPort(), "wrong result\nGetAgentPortshould be equal to%s", spew.Sdump(exp))
	}
	{
		environment := "DEV"
		os.Setenv(EnvKeyAutenticamiEnvironment, environment)
		appData := "~/appdata"
		os.Setenv(EnvKeyAutenticamiAgentAppData, appData)
		port := "ABC"
		os.Setenv(EnvKeyAutenticamiAgentPort, port)
		agentType := "PDP-AGENT"
 		_, err := NewAgentConfig(agentType)
		assert.NotNil(err, "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
		assert.False(errors.Is(authzIntAgentErrors.ErrAgentInvalidPort, errors.New("Sample errore")), "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
	}
	{
		environment := "DEV"
		os.Setenv(EnvKeyAutenticamiEnvironment, environment)
		appData := "a b c d e f g h i l m n o p q r s t u v w x y z"
		os.Setenv(EnvKeyAutenticamiAgentAppData, appData)
		port := "9091"
		os.Setenv(EnvKeyAutenticamiAgentPort, port)
		agentType := "PDP-AGENT"
 		_, err := NewAgentConfig(agentType)
		assert.NotNil(err, "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
		assert.False(errors.Is(authzIntAgentErrors.ErrAgentInvalidAppData, errors.New("Sample errore")), "wrong result\nerror shold be nil and not%s", spew.Sdump(err))
	}
}
