// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package targets

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSessionCredential_Tags(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	w := wrapper.TestWrapper(t)
	filter := &encrypt.Filter{
		Wrapper:  w,
		HmacSalt: []byte("salt"),
		HmacInfo: []byte("info"),
	}

	cred, err := structpb.NewStruct(map[string]any{
		"username": "svc@corp.example.com",
		"password": "super-secret",
	})
	require.NoError(t, err)

	decoded, err := structpb.NewStruct(map[string]any{
		"username": "svc@corp.example.com",
		"password": "super-secret",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		payload *SessionCredential
	}{
		{
			name: "credential-and-secret-fields-are-redacted",
			payload: &SessionCredential{
				CredentialSource: &CredentialSource{Id: "clvlt_abc123"},
				Secret: &SessionSecret{
					Raw:     "base64rawsecret",
					Decoded: decoded,
				},
				Credential: cred,
			},
		},
		{
			name:    "nil-credential-and-secret-no-error",
			payload: &SessionCredential{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := filter.Process(ctx, &eventlogger.Event{
				Type:      "test",
				CreatedAt: now,
				Payload:   tt.payload,
			})
			require.NoError(err)
			require.NotNil(got)

			b, err := json.Marshal(got)
			require.NoError(err)
			t.Log(string(b))

			// Credential and Decoded struct fields must be redacted
			if tt.payload.GetCredential() != nil {
				for k := range tt.payload.Credential.Fields {
					assert.NotContains(string(b), tt.payload.Credential.Fields[k].GetStringValue(),
						"Credential field %q should be redacted", k)
				}
			}
			if tt.payload.GetSecret().GetDecoded() != nil {
				for k := range tt.payload.Secret.Decoded.Fields {
					assert.NotContains(string(b), tt.payload.Secret.Decoded.Fields[k].GetStringValue(),
						"Decoded field %q should be redacted", k)
				}
			}
			if tt.payload.GetSecret().GetRaw() != "" {
				assert.NotContains(string(b), tt.payload.Secret.Raw, "Secret.Raw should be redacted")
			}
		})
	}
}
