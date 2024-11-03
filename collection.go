// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type Collection struct {
	m map[any]CMW
}

// Deserialize a JSON or CBOR collection
func (o *Collection) Deserialize(b []byte) error {
	switch b[0] {
	case 0x7b: // '{'
		return o.Unmarshal(JSON, b)
	default:
		return o.Unmarshal(CBOR, b)
	}
}

// Serialize the collection.  The type of serialization depends on the
// serialization specified for each item.  Items must have compatible
// serializations: CBORArray/CBORTag or JSON.
func (o *Collection) Serialize(s Serialization) ([]byte, error) {
	var b []byte
	var err error
	m := make(map[any][]byte)

	for i, v := range o.m {
		c, err := v.Serialize(s)
		if err != nil {
			return nil, fmt.Errorf("marshaling collection item %v: %w", i, err)
		}
		switch t := i.(type) {
		case string:
			m[t] = c
		case uint64:
			if s == JSON {
				return nil, errors.New("collection, key error: int64 illegal for JSON serialization")
			}
			m[t] = c
		default:
			return nil, fmt.Errorf("collection, key error: want string or int64, got %T", t)
		}
	}

	switch s {
	case CBOR:
		b, err = cbor.Marshal(m)
	case JSON:
		b, err = json.Marshal(m)
	default:
		return nil, fmt.Errorf("collection serialization format not supported: %d", s)
	}
	if err != nil {
		return nil, fmt.Errorf("marshaling collection: %w", err)
	}

	return b, nil
}

// GetMap returns a pointer to the internal map
func (o *Collection) GetMap() map[any]CMW {
	return o.m
}

// GetItem returns the CMW associated with label k
func (o *Collection) GetItem(k any) (CMW, error) {
	v, ok := o.m[k]
	if !ok {
		return CMW{}, fmt.Errorf("item not found for key %v", k)
	}
	return v, nil
}

// AddItem adds a new item with label k to the collection
func (o *Collection) AddItem(k any, c CMW) {
	if o.m == nil {
		o.m = make(map[any]CMW)
	}
	o.m[k] = c
}

// UnmarshalCBOR unmarshal the supplied CBOR buffer to a CMW collection
func (o *Collection) Unmarshal(s Serialization, b []byte) error {
	var tmp map[any][]byte
	var err error

	switch s {
	case CBOR:
		cbor.Unmarshal(b, &tmp)
	case JSON:
		json.Unmarshal(b, &tmp)
	default:
		return fmt.Errorf("collection serialization format not supported: %d", s)
	}
	if err != nil {
		return fmt.Errorf("unmarshaling collection: %w", err)
	}

	m := make(map[any]CMW)

	for k, v := range tmp {
		var c CMW
		if err := c.Deserialize(v); err != nil {
			return fmt.Errorf("unmarshaling collection item %v: %w", k, err)
		}
		m[k] = c
	}

	o.m = m

	return nil
}

func sniff_collection(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	if b[0] == 0x7b {
		return true
	} else if (b[0] >= 0xa0 && b[0] <= 0xbb) || b[0] == 0xbf {
		return true
	}

	return false
}
