// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"

	pkgAM "github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement"
	pkgPdp "github.com/autenticami/autenticami-authz/pkg/pdpagent"

	"github.com/google/uuid"
)

type PDPServer struct {
	UnimplementedPDPServiceServer
	Service pkgPdp.PDPService
}

func (s PDPServer) GetPermissionsState(ctx context.Context, req *PermissionsStateRequest) (*PermissionsStateResponse, error) {
	permissionsState, _ := s.Service.GetPermissionsState(pkgAM.UURString(req.Identity.Uur))
	if permissionsState == nil {
		return nil, errors.New("permission state cannot be built for the given identity")
	}
	permissions := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: req.Identity.GetUur(),
		},
		PermissionsState: &PermissionsState{
			Forbid: []*PolicyStatementWrapper{},
			Permit: []*PolicyStatementWrapper{},
		},
	}
	for i, wrapper := range permissionsState.GetForbidList() {
		permissions.PermissionsState.Forbid[i] = &PolicyStatementWrapper{
			Id: wrapper.Id.String(),
			StatmentStringified: wrapper.StatmentStringified,
			StatmentHashed: wrapper.StatmentHashed,
		}
	}
	return permissions, nil
}

func (s PDPServer) EvaluatePermissions(ctx context.Context, req *PermissionsEvaluationRequest) (*PermissionsEvaluationResponse, error) {
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
