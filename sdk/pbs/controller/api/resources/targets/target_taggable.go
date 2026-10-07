// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package targets

import (
	"fmt"

	"github.com/hashicorp/eventlogger/filters/encrypt"
)

// Tags implements the encrypt.Taggable interface which allows
// SessionCredential map fields to be classified for the encrypt filter.
// SessionCredential.Credential is a structpb.Struct whose keys are dynamic
// and cannot carry class: struct tags, so Taggable is required.
func (x *SessionCredential) Tags() ([]encrypt.PointerTag, error) {
	if x.GetCredential() == nil {
		return nil, nil
	}
	tags := make([]encrypt.PointerTag, 0, len(x.Credential.Fields))
	for k := range x.Credential.Fields {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        fmt.Sprintf("/Credential/Fields/%s", k),
			Classification: encrypt.SecretClassification,
			Filter:         encrypt.RedactOperation,
		})
	}
	return tags, nil
}

// Tags implements the encrypt.Taggable interface which allows
// SessionSecret map fields to be classified for the encrypt filter.
// SessionSecret.Decoded is a structpb.Struct whose keys are dynamic
// and cannot carry class: struct tags, so Taggable is required.
func (x *SessionSecret) Tags() ([]encrypt.PointerTag, error) {
	if x.GetDecoded() == nil {
		return nil, nil
	}
	tags := make([]encrypt.PointerTag, 0, len(x.Decoded.Fields))
	for k := range x.Decoded.Fields {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        fmt.Sprintf("/Decoded/Fields/%s", k),
			Classification: encrypt.SecretClassification,
			Filter:         encrypt.RedactOperation,
		})
	}
	return tags, nil
}
