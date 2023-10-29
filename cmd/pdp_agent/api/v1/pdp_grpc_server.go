// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	
	"github.com/google/uuid"
)

type PDPServer struct {
	UnimplementedPDPServiceServer
}

func (s *PDPServer) GetPermissionsState(ctx context.Context, req *PermissionsStateRequest) (*PermissionsStateResponse, error) {
	permissions := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: req.Identity.GetUur(),
		},
		PermissionsState: &PermissionsState{
			Forbid: []*PolicyStatementDescription{},
			Permit: []*PolicyStatementDescription{},
		},
	}
	return permissions, nil
}

func (s *PDPServer) EvaluatePermissions(ctx context.Context, req *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error) {
	permissionsEvaluation := &PermissionsEvaluationResponse{
		Identity: &Identity{
			Uur: req.Identity.GetUur(),
		},
		Evaluations: make([]*PermissionsEvaluationOutcome, len(req.Evaluations)),
		Allowed:     true,
	}
	for i, evaluation := range req.Evaluations {
		outcome := &PermissionsEvaluationOutcome{
			Evaluation: evaluation,
			Allowed:    true,
			Explanation: &PermissionsEvaluationOutcomeExplanation{
				IsExplicitlyDenied: true,
				IsImplicitlyDenied: false,
			},
		}
		if len(outcome.Evaluation.Id) == 0 {
			outcome.Evaluation.Id = uuid.New().String()
		}
		permissionsEvaluation.Evaluations[i] = outcome
	}
	return permissionsEvaluation, nil
}
