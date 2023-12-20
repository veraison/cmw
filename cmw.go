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
	UnknownSerialization = Serialization(iota)
	JSONArray
	CBORArray
	CBORTag
)

// a CMW object holds the internal representation of a RATS conceptual message
// wrapper
type CMW struct {
	typ           Type
	val           Value
	ind           Indicator
	serialization Serialization
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
func (o *CMW) SetSerialization(s Serialization) { o.serialization = s }

func (o CMW) GetValue() []byte                { return o.val }
func (o CMW) GetType() string                 { return o.typ.String() }
func (o CMW) GetIndicator() Indicator         { return o.ind }
func (o CMW) GetSerialization() Serialization { return o.serialization }

// Deserialize a CMW
func (o *CMW) Deserialize(b []byte) error {
	s := sniff(b)

	o.serialization = s

	switch s {
	case JSONArray:
		return o.UnmarshalJSON(b)
	case CBORArray, CBORTag:
		return o.UnmarshalCBOR(b)
	}

	return errors.New("unknown CMW format")
}

// Serialize a CMW according to its provided Serialization
func (o CMW) Serialize() ([]byte, error) {
	s := o.serialization
	switch s {
	case JSONArray:
		return o.MarshalJSON()
	case CBORArray, CBORTag:
		return o.MarshalCBOR()
	}
	return nil, fmt.Errorf("invalid serialization format %d", s)
}

func (o CMW) MarshalJSON() ([]byte, error) { return arrayEncode(json.Marshal, &o) }

func (o CMW) MarshalCBOR() ([]byte, error) {
	s := o.serialization
	switch s {
	case CBORArray:
		return arrayEncode(cbor.Marshal, &o)
	case CBORTag:
		return o.encodeCBORTag()
	}
	return nil, fmt.Errorf("invalid serialization format: want CBORArray or CBORTag, got %d", s)
}

func (o CMW) encodeCBORTag() ([]byte, error) {
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
	if arrayDecode[cbor.RawMessage](cbor.Unmarshal, b, o) == nil {
		o.serialization = CBORArray
		return nil
	}

	if o.decodeCBORTag(b) == nil {
		// the serialization attribute is set by decodeCBORTag
		return nil
	}

	return errors.New("invalid CBOR-encoded CMW")
}

func (o *CMW) UnmarshalJSON(b []byte) error {
	err := arrayDecode[json.RawMessage](json.Unmarshal, b, o)
	o.serialization = JSONArray
	return err
}

func (o *CMW) decodeCBORTag(b []byte) error {
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
	o.serialization = CBORTag

	return nil
}

func sniff(b []byte) Serialization {
	if len(b) == 0 {
		return UnknownSerialization
	}

	if b[0] == 0x82 || b[0] == 0x83 {
		return CBORArray
	} else if b[0] >= 0xc0 && b[0] <= 0xdb {
		return CBORTag
	} else if b[0] == 0x5b {
		return JSONArray
	}

	return UnknownSerialization
}

type (
	arrayDecoder func([]byte, any) error
	arrayEncoder func(any) ([]byte, error)
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

	a := []any{o.typ, o.val}

	if !o.ind.Empty() {
		a = append(a, o.ind)
	}

	return enc(a)
}
