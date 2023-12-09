// Copyright (c) Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/autenticami/autenticami-authz/pkg/iam/accessmanagement/policies"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestPermissionsStateCreation(t *testing.T) {
	tests := map[string]struct {
		Path       string
		InputFiles func() []string
	}{
		string(policies.PolicyV1): {
			"./testdata/permissions-states/creation",
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			testDataCasePath := testDataVersionPath + "/" + name
			t.Run(strings.ToUpper(version+"-"+name), func(t *testing.T) {
				assert := assert.New(t)
				permState := newPermissionsState()
				totPermitted, totFobidden := 0, 0
				for _, input := range test.InputFiles() {
					bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
					data := policies.ACLPolicy{}
					_ = json.Unmarshal(bArray, &data)
					var err error
					err = permState.fobidACLPolicyStatements(data.Forbid)
					assert.Nil(err, "wrong result\nshould be nil")
					totPermitted += len(data.Permit)
					err = permState.permitACLPolicyStatements(data.Permit)
					assert.Nil(err, "wrong result\nshould be nil")
					totFobidden += len(data.Forbid)
				}

				var got, want int

				got = len(permState.GetPermitList())
				want = totPermitted
				assert.Equal(got, want, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))

				got = len(permState.GetForbidList())
				want = totFobidden
				assert.Equal(got, want, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(want))
			})
		}
	}
}

func TestMiscellaneousPermissionsState(t *testing.T) {
	assert := assert.New(t)
	{
		permState := newPermissionsState()
		err := permState.fobidACLPolicyStatements([]*policies.PolicyStatement{nil})
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
	{
		permState := newPermissionsState()
		err := permState.permitACLPolicyStatements([]*policies.PolicyStatement{nil})
		assert.NotNil(err, "wrong result\nshould be not nil")
	}
}
