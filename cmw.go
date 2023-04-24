// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type Serialization uint

const (
	JSONArray = Serialization(iota)
	CBORArray
	CBORTag
	Unknown
)

// a CMW object holds the internal representation of a RATS conceptual message
// wrapper
type CMW struct {
	typ Type
	val Value
	ind Indicator
}

func (o *CMW) SetMediaType(v string)     { _ = o.typ.Set(v) }
func (o *CMW) SetContentFormat(v uint16) { _ = o.typ.Set(v) }
func (o *CMW) SetTagNumber(v uint64)     { _ = o.typ.Set(v) }
func (o *CMW) SetValue(v []byte)         { _ = o.val.Set(v) }
func (o *CMW) SetIndicators(indicators ...Indicator) {
	var v Indicator

	for _, ind := range indicators {
		v.Set(ind)
	}

	o.ind = v
}

func (o CMW) GetValue() []byte        { return o.val }
func (o CMW) GetType() string         { return o.typ.String() }
func (o CMW) GetIndicator() Indicator { return o.ind }

// Deserialize a CMW
func (o *CMW) Deserialize(b []byte) error {
	switch sniff(b) {
	case JSONArray:
		return o.UnmarshalJSON(b)
	case CBORArray:
		return o.UnmarshalCBOR(b)
	case CBORTag:
		return o.UnmarshalCBORTag(b)
	}
	return errors.New("unknown CMW format")
}

// Serialize a CMW according to the provided Serialization
func (o CMW) Serialize(s Serialization) ([]byte, error) {
	switch s {
	case JSONArray:
		return o.MarshalJSON()
	case CBORArray:
		return o.MarshalCBOR()
	case CBORTag:
		return o.MarshalCBORTag()
	}
	return nil, fmt.Errorf("invalid serialization format %d", s)
}

func (o CMW) MarshalJSON() ([]byte, error) { return arrayEncode(json.Marshal, &o) }
func (o CMW) MarshalCBOR() ([]byte, error) { return arrayEncode(cbor.Marshal, &o) }

func (o CMW) MarshalCBORTag() ([]byte, error) {
	var (
		tag cbor.RawTag
		err error
	)

	if !o.typ.IsSet() || !o.val.IsSet() {
		return nil, fmt.Errorf("type and value MUST be set in CMW")
	}

	tag.Number, err = o.typ.TagNumber()
	if err != nil {
		return nil, fmt.Errorf("getting a suitable tag value: %w", err)
	}

	tag.Content, err = cbor.Marshal(o.val)
	if err != nil {
		return nil, fmt.Errorf("marshaling tag value: %w", err)
	}

	return tag.MarshalCBOR()
}

func (o *CMW) UnmarshalCBOR(b []byte) error {
	return arrayDecode[cbor.RawMessage](cbor.Unmarshal, b, o)
}

func (o *CMW) UnmarshalJSON(b []byte) error {
	return arrayDecode[json.RawMessage](json.Unmarshal, b, o)
}

func (o *CMW) UnmarshalCBORTag(b []byte) error {
	var (
		v   cbor.RawTag
		m   []byte
		err error
	)

	if err = v.UnmarshalCBOR(b); err != nil {
		return fmt.Errorf("unmarshal CMW CBOR Tag: %w", err)
	}

	if err = cbor.Unmarshal(v.Content, &m); err != nil {
		return fmt.Errorf("unmarshal CMW CBOR Tag bstr-wrapped value: %w", err)
	}

	_ = o.typ.Set(v.Number)
	_ = o.val.Set(m)

	return nil
}

func sniff(b []byte) Serialization {
	if len(b) == 0 {
		return Unknown
	}

	if b[0] == 0x82 || b[0] == 0x83 {
		return CBORArray
	} else if b[0] >= 0xc0 && b[0] <= 0xdb {
		return CBORTag
	} else if b[0] == 0x5b {
		return JSONArray
	}

	return Unknown
}

type (
	arrayDecoder func([]byte, interface{}) error
	arrayEncoder func(interface{}) ([]byte, error)
)

func arrayDecode[V json.RawMessage | cbor.RawMessage](
	dec arrayDecoder, b []byte, o *CMW,
) error {
	var a []V

	if err := dec(b, &a); err != nil {
		return err
	}

	alen := len(a)

	if alen < 2 || alen > 3 {
		return fmt.Errorf("wrong number of entries (%d) in the CMW array", alen)
	}

	if err := dec(a[0], &o.typ); err != nil {
		return fmt.Errorf("unmarshaling type: %w", err)
	}

	if err := dec(a[1], &o.val); err != nil {
		return fmt.Errorf("unmarshaling value: %w", err)
	}

	if alen == 3 {
		if err := dec(a[2], &o.ind); err != nil {
			return fmt.Errorf("unmarshaling indicator: %w", err)
		}
	}

	return nil
}

func arrayEncode(enc arrayEncoder, o *CMW) ([]byte, error) {
	if !o.typ.IsSet() || !o.val.IsSet() {
		return nil, fmt.Errorf("type and value MUST be set in CMW")
	}

	a := []interface{}{o.typ, o.val}

	if !o.ind.Empty() {
		a = append(a, o.ind)
	}

	return enc(a)
}
