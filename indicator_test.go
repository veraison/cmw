// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Indicator_misc(t *testing.T) {
	var i Indicator

	assert.True(t, i.Empty())
	assert.False(t, i.Has(AttestationResults))
	assert.False(t, i.Has(ReferenceValues))
	assert.False(t, i.Has(Endorsements))
	assert.False(t, i.Has(Evidence))
	assert.False(t, i.Has(TrustAnchors))

	i.Set(AttestationResults)
	assert.True(t, i.Has(AttestationResults))
	assert.False(t, i.Has(ReferenceValues))
	assert.False(t, i.Has(Endorsements))
	assert.False(t, i.Has(Evidence))
	assert.False(t, i.Has(TrustAnchors))

	i.Clear(AttestationResults)
	assert.True(t, i.Empty())

	i.Set(AttestationResults)
	assert.False(t, i.Empty())
	i.Toggle(AttestationResults)
	assert.True(t, i.Empty())

	i.Set(AttestationResults)
	i.Set(ReferenceValues)
	i.Set(Evidence)
	i.Set(Endorsements)
	i.Set(TrustAnchors)
	assert.True(t, i.Has(AttestationResults))
	assert.True(t, i.Has(ReferenceValues))
	assert.True(t, i.Has(Endorsements))
	assert.True(t, i.Has(Evidence))
	assert.True(t, i.Has(TrustAnchors))
}
