// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	"crypto/sha256"
	"fmt"

	pkgiCore "github.com/autenticami/autenticami-authz/pkg/internal/core"

	"github.com/google/uuid"
)

type PolicyStatementWrapper struct {
	Id                  uuid.UUID
	Statement           PolicyStatement
	StatmentStringified string
	StatmentHashed      string
	// sanitizedStatement           *PolicyStatement
	// sanitizedStatmentStringified string
	// sanitizedStatmentHashed      string
}

type PermissionsState struct {
	duplicates map[uuid.UUID]uuid.UUID
	forbid     []*PolicyStatementWrapper
	permit     []*PolicyStatementWrapper
}

func createPolicyStatementWrapper(policyStatement *PolicyStatement) (*PolicyStatementWrapper, error) {
	if policyStatement == nil {
		return nil, ErrAccessManagementInvalidDataType
	}
	policyStatementString, err := pkgiCore.Stringify(policyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(policyStatementString))
	bs := h.Sum(nil)
	policyStatementHash := fmt.Sprintf("%x", bs)
	return &PolicyStatementWrapper{
		Id:                  uuid.New(),
		Statement:           *policyStatement,
		StatmentStringified: policyStatementString,
		StatmentHashed:      policyStatementHash,
	}, nil
}

func createPolicyStatementWrappers(policyStatements []PolicyStatement) ([]*PolicyStatementWrapper, error) {
	wrappers := make([]*PolicyStatementWrapper, len(policyStatements))
	for i, policyStatement := range policyStatements {
		wrapper, err := createPolicyStatementWrapper(&policyStatement)
		if err != nil {
			return nil, err
		}
		wrappers[i] = wrapper
	}
	return wrappers, nil
}

func newPermissionsState() *PermissionsState {
	return &PermissionsState{
		duplicates: map[uuid.UUID]uuid.UUID{},
		forbid:     make([]*PolicyStatementWrapper, 0),
		permit:     make([]*PolicyStatementWrapper, 0),
	}
}

func (b *PermissionsState) DenyACLPolicyStatements(policyStatements []PolicyStatement) error {
	wrappers, err := createPolicyStatementWrappers(policyStatements)
	if err != nil {
		return err
	}
	b.forbid = append(b.forbid, wrappers...)
	return nil
}

func (b *PermissionsState) AllowACLPolicyStatements(policyStatements []PolicyStatement) error {
	wrappers, err := createPolicyStatementWrappers(policyStatements)
	if err != nil {
		return err
	}
	b.permit = append(b.permit, wrappers...)
	return nil
}

func (b *PermissionsState) GetForbidList() []PolicyStatementWrapper {
	list := make([]PolicyStatementWrapper, len(b.forbid))
	for i, forbid := range b.forbid {
		list[i] = *forbid
	}
	return list
}

func (b *PermissionsState) GetPermitList() []PolicyStatementWrapper {
	list := make([]PolicyStatementWrapper, len(b.permit))
	for i, permit := range b.permit {
		list[i] = *permit
	}
	return list
}
