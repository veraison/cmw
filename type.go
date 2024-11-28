// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"fmt"
	"mime"
	"strconv"
)

type Type struct {
	val any
}

func mtFromCf(cf uint16) string {
	mt, ok := cf2mt[cf]
	if ok {
		return mt
	}
	return strconv.FormatUint(uint64(cf), 10)
}

func (o Type) String() string {
	switch v := o.val.(type) {
	case string:
		return v
	case uint16:
		return mtFromCf(v)
	case uint64:
		cf, err := CF(v)
		if err != nil {
			return ""
		}
		return mtFromCf(cf)
	default:
		return ""
	}
}

func (o Type) MarshalJSON() ([]byte, error) { return typeEncode(json.Marshal, &o) }
func (o Type) MarshalCBOR() ([]byte, error) { return typeEncode(em.Marshal, &o) }

func (o *Type) UnmarshalJSON(b []byte) error { return typeDecode(json.Unmarshal, b, o) }
func (o *Type) UnmarshalCBOR(b []byte) error { return typeDecode(dm.Unmarshal, b, o) }

type (
	typeDecoder func([]byte, any) error
	typeEncoder func(any) ([]byte, error)
)

func typeDecode(dec typeDecoder, b []byte, o *Type) error {
	var v any

	if err := dec(b, &v); err != nil {
		return fmt.Errorf("cannot unmarshal JSON type: %w", err)
	}

	switch t := v.(type) {
	case string:
		o.val = t
	case float64: // JSON
		if t == float64(uint16(t)) {
			o.val = uint16(t)
		} else {
			return fmt.Errorf("cannot unmarshal %f into uint16", t)
		}
	case uint64: // CBOR
		if t == uint64(uint16(t)) {
			o.val = uint16(t)
		} else {
			return fmt.Errorf("cannot unmarshal %d into uint16", t)
		}
	default:
		return fmt.Errorf("expecting string or uint16, got %T", t)
	}

	return nil
}

func typeEncode(enc typeEncoder, o *Type) ([]byte, error) {
	switch t := o.val.(type) {
	case string:
	case uint16:
		break
	default:
		return nil, fmt.Errorf("wrong type for Type (%T)", t)
	}

	return enc(o.val)
}

func (o Type) TagNumber() (uint64, error) {
	switch v := o.val.(type) {
	case string:
		cf, ok := mt2cf[v]
		if !ok {
			return 0, fmt.Errorf("media type %q has no registered CoAP Content-Format", v)
		}
		return TN(cf)
	case uint16:
		return TN(v)
	case uint64:
		return v, nil
	default:
		return 0, fmt.Errorf("cannot get tag number for %T", v)
	}
}

func (o Type) IsSet() bool {
	if o.val == nil {
		return false
	}

	switch t := o.val.(type) {
	case string:
		if t == "" {
			return false
		}
	}

	return true
}

func (o *Type) Set(v any) error {
	switch t := v.(type) {
	case string:
		if _, _, err := mime.ParseMediaType(t); err != nil {
			return fmt.Errorf("bad media type: %w", err)
		}
	case uint64, uint16:
		// no checks needed
	default:
		return fmt.Errorf("unsupported type %T for CMW type", t)
	}

	o.val = v

	return nil
}
