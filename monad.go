package cmw

import (
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type monad struct {
	typ Type
	val Value
	ind Indicator

	format Format
}

func (o monad) getType() string         { return o.typ.String() }
func (o monad) getValue() []byte        { return o.val }
func (o monad) getIndicator() Indicator { return o.ind }

func (o monad) MarshalJSON() ([]byte, error) { return recordEncode(json.Marshal, &o) }

func (o *monad) UnmarshalJSON(b []byte) error {
	if err := recordDecode[json.RawMessage](json.Unmarshal, b, o); err != nil {
		return err
	}

	o.format = FormatJSONRecord

	return nil
}

func (o monad) MarshalCBOR() ([]byte, error) {
	s := o.format
	switch s {
	case FormatCBORRecord, FormatUnknown: // XXX if it is not explicitly set, use the record format
		return recordEncode(em.Marshal, &o)
	case FormatCBORTag:
		return o.encodeCBORTag()
	}
	// unreachable
	panic(fmt.Sprintf("invalid format: want CBOR record or CBOR Tag, got %s", Format(s)))
}

func (o *monad) UnmarshalCBOR(b []byte) error {
	if startCBORRecord(b[0]) {
		if err := recordDecode[cbor.RawMessage](dm.Unmarshal, b, o); err != nil {
			return fmt.Errorf("decoding record: %w", err)
		}
		o.format = FormatCBORRecord
	} else if startCBORTag(b[0]) {
		if err := o.decodeCBORTag(b); err != nil {
			return fmt.Errorf("decoding tag: %w", err)
		}
		o.format = FormatCBORTag
	} else {
		// unreachable
		panic(fmt.Sprintf("want CBOR Tag or CBOR array, got 0x%02x", b[0]))
	}

	return nil
}

func (o monad) encodeCBORTag() ([]byte, error) {
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

	tag.Content, err = em.Marshal(o.val)
	if err != nil {
		return nil, fmt.Errorf("marshaling tag value: %w", err)
	}

	return tag.MarshalCBOR()
}

func (o *monad) decodeCBORTag(b []byte) error {
	var (
		v   cbor.RawTag
		m   []byte
		err error
	)

	if err = v.UnmarshalCBOR(b); err != nil {
		return fmt.Errorf("unmarshal CMW CBOR Tag: %w", err)
	}

	if err = dm.Unmarshal(v.Content, &m); err != nil {
		return fmt.Errorf("unmarshal CMW CBOR Tag bstr-wrapped value: %w", err)
	}

	if err = o.typ.Set(v.Number); err != nil {
		return fmt.Errorf("setting type: %w", err)
	}
	if err = o.val.Set(m); err != nil {
		return fmt.Errorf("setting value: %w", err)
	}
	o.format = FormatCBORTag

	return nil
}

type (
	recordDecoder func([]byte, any) error
	recordEncoder func(any) ([]byte, error)
)

func recordDecode[V json.RawMessage | cbor.RawMessage](
	dec recordDecoder, b []byte, o *monad,
) error {
	var a []V

	if err := dec(b, &a); err != nil {
		return err
	}

	alen := len(a)

	if alen < 2 || alen > 3 {
		return fmt.Errorf("wrong number of entries (%d) in the CMW record", alen)
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

func recordEncode(enc recordEncoder, o *monad) ([]byte, error) {
	if !o.typ.IsSet() || !o.val.IsSet() {
		return nil, fmt.Errorf("type and value MUST be set in CMW")
	}

	a := []any{o.typ, o.val}

	if !o.ind.Empty() {
		a = append(a, o.ind)
	}

	return enc(a)
}
