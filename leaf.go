// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type LeafForm uint

const (
	UnknownForm = LeafForm(iota)
	JSONArray
	CBORArray
	CBORTag
	CBORTunnel
	JSONTunnel
)

// a Leaf object holds the internal representation of a RATS conceptual message
// wrapper
type Leaf struct {
	typ  Type
	val  Value
	ind  Indicator
	form LeafForm
}

func (o *Leaf) SetMediaType(v string)     { _ = o.typ.Set(v) }
func (o *Leaf) SetContentFormat(v uint16) { _ = o.typ.Set(v) }
func (o *Leaf) SetTagNumber(v uint64)     { _ = o.typ.Set(v) }
func (o *Leaf) SetValue(v []byte)         { _ = o.val.Set(v) }
func (o *Leaf) SetIndicators(indicators ...Indicator) {
	var v Indicator

	for _, ind := range indicators {
		v.Set(ind)
	}

	o.ind = v
}
func (o *Leaf) SetForm(s LeafForm) { o.form = s }

func (o Leaf) GetValue() []byte        { return o.val }
func (o Leaf) GetType() string         { return o.typ.String() }
func (o Leaf) GetIndicator() Indicator { return o.ind }
func (o Leaf) GetForm() LeafForm       { return o.form }

// Deserialize a CMW
func (o *Leaf) Deserialize(b []byte) error {
	f := sniff_leaf(b)
	if f == UnknownForm {
		return errors.New("unknown leaf CMW format")
	}
	o.form = f

	switch f {
	case JSONArray:
		return o.UnmarshalJSON(b)
	case CBORArray, CBORTag:
		return o.UnmarshalCBOR(b)
	case CBORTunnel:
		return o.UnmarshalCBORTunnel(b)
	case JSONTunnel:
		return o.UnmarshalJSONTunnel(b)
	default:
		return errors.New("unknown leaf CMW format")
	}
}

// Serialize a CMW according to to the provided serialization
func (o Leaf) Serialize(s Serialization) ([]byte, error) {
	var b []byte
	var err error
	f := o.form
	tunnel := !o.isCompatibleWithSerialization(s)
	switch f {
	case JSONArray:
		b, err = o.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal leaf CMW: %w", err)
		}
		if tunnel {
			return serializeJsonToCbor(b)
		}
		return b, nil
	case CBORArray, CBORTag:
		b, err = o.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal leaf CMW: %w", err)
		}
		if tunnel {
			return serializeCborToJson(b)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("invalid leaf form %d", f)
	}
}

func (o Leaf) MarshalJSON() ([]byte, error) { return arrayEncode(json.Marshal, &o) }

func (o Leaf) MarshalCBOR() ([]byte, error) {
	f := o.form
	switch f {
	case CBORArray:
		return arrayEncode(cbor.Marshal, &o)
	case CBORTag:
		return o.encodeCBORTag()
	}
	return nil, fmt.Errorf("invalid serialization format: want CBORArray or CBORTag, got %d", f)
}

func (o Leaf) encodeCBORTag() ([]byte, error) {
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

func (o *Leaf) UnmarshalCBOR(b []byte) error {
	if arrayDecode[cbor.RawMessage](cbor.Unmarshal, b, o) == nil {
		o.form = CBORArray
		return nil
	}

	if o.decodeCBORTag(b) == nil {
		// the serialization attribute is set by decodeCBORTag
		return nil
	}

	return errors.New("invalid CBOR-encoded CMW")
}

func (o *Leaf) UnmarshalCBORTunnel(b []byte) error {
	var err error
	b, err = deserializeCborToJson(b)
	if err != nil {
		return fmt.Errorf("failed to unmarshal CBOR-to-JSON tunnel: %w", err)
	}
	o.form = sniff_leaf(b)
	return o.UnmarshalJSON(b)
}

func (o *Leaf) UnmarshalJSON(b []byte) error {
	err := arrayDecode[json.RawMessage](json.Unmarshal, b, o)
	o.form = JSONArray
	return err
}

func (o *Leaf) UnmarshalJSONTunnel(b []byte) error {
	var err error
	b, err = deserializeJsonToCbor(b)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON-to-CBOR tunnel: %w", err)
	}
	o.form = sniff_leaf(b)
	return o.UnmarshalCBOR(b)
}

func (o *Leaf) decodeCBORTag(b []byte) error {
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
	o.form = CBORTag

	return nil
}

func sniff_leaf(b []byte) LeafForm {
	if len(b) == 0 {
		return UnknownForm
	}

	if len(b) > 3 {
		// c2j-tunnel starts with `["#` encoded as UTF-8: [0x5b, 0x22, 0x23]
		// j2c-tunnel starts with:
		// 82            # array(2)
		//   6f	         # text(15)
		//       23...   # "#..."
		if b[0] == 0x5b && b[1] == 0x22 && b[2] == 0x23 {
			return CBORTunnel
		} else if b[0] == 0x82 && b[1] == 0x6F && b[2] == 0x23 {
			return JSONTunnel
		}
	}

	if b[0] == 0x82 || b[0] == 0x83 {
		return CBORArray
	} else if b[0] >= 0xc0 && b[0] <= 0xdb {
		return CBORTag
	} else if b[0] == 0x5b {
		return JSONArray
	}

	return UnknownForm
}

type (
	arrayDecoder func([]byte, any) error
	arrayEncoder func(any) ([]byte, error)
)

func arrayDecode[V json.RawMessage | cbor.RawMessage](
	dec arrayDecoder, b []byte, o *Leaf,
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

func arrayEncode(enc arrayEncoder, o *Leaf) ([]byte, error) {
	if !o.typ.IsSet() || !o.val.IsSet() {
		return nil, fmt.Errorf("type and value MUST be set in CMW")
	}

	a := []any{o.typ, o.val}

	if !o.ind.Empty() {
		a = append(a, o.ind)
	}

	return enc(a)
}

func (o Leaf) isCompatibleWithSerialization(s Serialization) bool {
	switch s {
	case JSON:
		return o.form == JSONArray
	case CBOR:
		return o.form == CBORArray || o.form == CBORTag
	}

	return false
}
