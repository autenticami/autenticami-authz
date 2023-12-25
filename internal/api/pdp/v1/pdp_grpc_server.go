// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
	"log"

	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/permissions"
	"github.com/autenticami/autenticami-authz/pkg/accesscontrol/policies"
)

type PDPService interface {
	Setup() error
	GetPermissionsState(identityUUR policies.UURString, settings ...permissions.PermissionsEngineOption) (*permissions.PermissionsState, error)
}

type PDPServer struct {
	UnimplementedPDPServiceServer
	Service PDPService
}

func (s PDPServer) GetPermissionsState(ctx context.Context, req *PermissionsStateRequest) (*PermissionsStateResponse, error) {
	identityUUR := policies.UURString(req.Identity.Uur)
	isValid, err := identityUUR.IsValid(policies.PolicyLatest)
	if err != nil {
		log.Fatalf("error while validating identity UUR: %v", err)
		return nil, errors.New("Identity UUR is not valid")
	}
	if !isValid {
		return nil, errors.New("Identity UUR is not valid")
	}
	var permState *permissions.PermissionsState
	if req.PermissionsEngine != nil {
		virtualState := req.PermissionsEngine.VirtualState
		virtualStateViewIsCombinded := virtualState.View == VirtualState_COMBINED
		settings := []permissions.PermissionsEngineOption{
			permissions.WithPermissionsEngineVirtualState(virtualState.Enabled),
			permissions.WithPermissionsEngineVirtualStateViewCombined(virtualStateViewIsCombinded),
		}
		permState, err = s.Service.GetPermissionsState(identityUUR, settings[:]...)
	} else {
		permState, err = s.Service.GetPermissionsState(identityUUR)
	}
	if err != nil {
		log.Fatalf("error while getting permissions state: %v", err)
	}
	if permState == nil {
		return nil, errors.New("permission state cannot be built for the given identity")
	}
	return mapToPermissionsStateResponse(req.Identity.GetUur(), permState)
}

func (s PDPServer) EvaluatePermissions(ctx context.Context, req *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error) {
	permissionsEvaluation := &PermissionsEvaluationResponse{
		Identity: &Identity{
			Uur: req.Identity.GetUur(),
		},
		Evaluations: make([]*PermissionsEvaluationOutcome, len(req.Evaluations)),
		Permitted:   true,
	}
	for i, evaluation := range req.Evaluations {
		outcome := &PermissionsEvaluationOutcome{
			Evaluation: evaluation,
			Permitted:  false,
			Explanation: &PermissionsEvaluationOutcomeExplanation{
				IsExplicitlyForbidden: true,
				IsImplicitlyForbidden: false,
			},
		}
		permissionsEvaluation.Evaluations[i] = outcome
	}
	return permissionsEvaluation, nil
}
