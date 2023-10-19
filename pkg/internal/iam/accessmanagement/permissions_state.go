// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package accessmanagement

import (
	"crypto/sha256"
	"fmt"

	"github.com/autenticami/autenticami-authz/pkg/internal/core"
	"github.com/google/uuid"
)

type policyStatementWrapper struct {
	id                  uuid.UUID
	statement           *PolicyStatement
	statmentStringified string
	statmentHashed      string
	// sanitizedStatement           *PolicyStatement
	// sanitizedStatmentStringified string
	// sanitizedStatmentHashed      string
}

type PermissionsState struct {
	duplicates map[uuid.UUID]uuid.UUID
	forbid     []*policyStatementWrapper
	permit     []*policyStatementWrapper
}

func createPolicyStatementWrapper(policyStatement *PolicyStatement) (*policyStatementWrapper, error) {
	if policyStatement == nil {
		return nil, ErrAccessManagementInvalidDataType
	}
	policyStatementString, err := core.Stringify(policyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(policyStatementString))
	bs := h.Sum(nil)
	policyStatementHash := fmt.Sprintf("%x", bs)
	return &policyStatementWrapper{
		id:                  uuid.New(),
		statement:           policyStatement,
		statmentStringified: policyStatementString,
		statmentHashed:      policyStatementHash,
	}, nil
}

func createPolicyStatementWrappers(policyStatements []PolicyStatement) ([]*policyStatementWrapper, error) {
	wrappers := make([]*policyStatementWrapper, len(policyStatements))
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
		forbid:     make([]*policyStatementWrapper, 0),
		permit:     make([]*policyStatementWrapper, 0),
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
