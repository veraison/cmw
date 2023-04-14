// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

type Indicator uint

const (
	ReferenceValues = 1 << iota
	Endorsements
	Evidence
	AttestationResults
	TrustAnchors
)

const IndicatorNone = 0

func (o *Indicator) Set(v Indicator)     { *o |= v }
func (o *Indicator) Clear(v Indicator)   { *o &= ^v }
func (o *Indicator) Toggle(v Indicator)  { *o ^= v }
func (o Indicator) Has(v Indicator) bool { return o&v != 0 }
func (o Indicator) Empty() bool          { return o == IndicatorNone }
