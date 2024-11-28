// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"sort"
	"strings"
)

// Indicator is the internal representation of the `ind` bit map
type Indicator uint

const (
	ReferenceValues = 1 << iota
	Endorsements
	Evidence
	AttestationResults
	TrustAnchors
)

const IndicatorNone = 0

var indMap = map[Indicator]string{
	ReferenceValues:    "reference values",
	Endorsements:       "endorsements",
	Evidence:           "evidence",
	AttestationResults: "attestation results",
}

func (o *Indicator) Set(v Indicator)     { *o |= v }
func (o *Indicator) Clear(v Indicator)   { *o &= ^v }
func (o *Indicator) Toggle(v Indicator)  { *o ^= v }
func (o Indicator) Has(v Indicator) bool { return o&v != 0 }
func (o Indicator) Empty() bool          { return o == IndicatorNone }
func (o Indicator) String() string {
	var a []string

	for k, v := range indMap {
		if o.Has(k) {
			a = append(a, v)
		}
	}

	sort.Strings(a)

	return strings.Join(a, ", ")
}
