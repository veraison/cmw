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

type CollectionSerialization uint

const (
	UnknownCollectionSerialization = CollectionSerialization(iota)
	CollectionSerializationJSON
	CollectionSerializationCBOR
)

// Deserialize a JSON or CBOR collection
func (o *Collection) Deserialize(b []byte) error {
	switch b[0] {
	case 0x7b: // '{'
		return o.UnmarshalJSON(b)
	default:
		return o.UnmarshalCBOR(b)
	}
}

// Serialize the collection.  The type of serialization depends on the
// serialization specified for each item.  Items must have compatible
// serializations: CBORArray/CBORTag or JSON.
func (o *Collection) Serialize() ([]byte, error) {
	s, err := o.detectSerialization()
	if err != nil {
		return nil, err
	}

	switch s {
	case CollectionSerializationCBOR:
		return o.MarshalCBOR()
	case CollectionSerializationJSON:
		return o.MarshalJSON()
	default:
		return nil, errors.New("unsupported serialization")
	}
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

// MarshalJSON serializes the collection to JSON
func (o Collection) MarshalJSON() ([]byte, error) {
	m := make(map[string]json.RawMessage)

	for i, v := range o.m {
		c, err := v.Serialize()
		if err != nil {
			return nil, fmt.Errorf("marshaling JSON collection item %v: %w", i, err)
		}
		switch t := i.(type) {
		case string:
			m[t] = c
		default:
			return nil, fmt.Errorf("JSON collection, key error: want string, got %T", t)
		}
	}

	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling JSON collection: %w", err)
	}

	return b, nil
}

// MarshalCBOR serializes the collection to CBOR
func (o Collection) MarshalCBOR() ([]byte, error) {
	m := make(map[any]cbor.RawMessage)

	for i, v := range o.m {
		c, err := v.Serialize()
		if err != nil {
			return nil, fmt.Errorf("marshaling CBOR collection item %v: %w", i, err)
		}
		switch t := i.(type) {
		case string, uint64:
			m[t] = c
		default:
			return nil, fmt.Errorf("CBOR collection, key error: want string or int64, got %T", t)
		}
	}

	b, err := cbor.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling CBOR collection: %w", err)
	}

	return b, nil
}

// UnmarshalCBOR unmarshal the supplied CBOR buffer to a CMW collection
func (o *Collection) UnmarshalCBOR(b []byte) error {
	var tmp map[any]cbor.RawMessage

	if err := cbor.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("unmarshaling CBOR collection: %w", err)
	}

	m := make(map[any]CMW)

	for k, v := range tmp {
		var c CMW
		if err := c.Deserialize(v); err != nil {
			return fmt.Errorf("unmarshaling CBOR collection item %v: %w", k, err)
		}
		m[k] = c
	}

	o.m = m

	return nil
}

// UnmarshalJSON unmarshals the supplied JSON buffer to a CMW collection
func (o *Collection) UnmarshalJSON(b []byte) error {
	var tmp map[string]json.RawMessage

	if err := json.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("unmarshaling JSON collection: %w", err)
	}

	m := make(map[any]CMW)

	for k, v := range tmp {
		var c CMW
		if err := c.Deserialize(v); err != nil {
			return fmt.Errorf("unmarshaling JSON collection item %v: %w", k, err)
		}
		m[k] = c
	}

	o.m = m

	return nil
}

func (o Collection) detectSerialization() (CollectionSerialization, error) {
	rec := make(map[CollectionSerialization]bool)

	s := UnknownCollectionSerialization

	for k, v := range o.m {
		switch v.serialization {
		case CBORArray, CBORTag:
			s = CollectionSerializationCBOR
			rec[s] = true
		case JSONArray:
			s = CollectionSerializationJSON
			rec[s] = true
		default:
			return UnknownCollectionSerialization,
				fmt.Errorf(
					"serialization not defined for collection item with k %v", k,
				)
		}
	}

	if len(rec) != 1 {
		return UnknownCollectionSerialization,
			errors.New("CMW collection has items with incompatible serializations")
	}

	return s, nil
}
