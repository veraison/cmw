// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"errors"
	"fmt"
)

type Serialization uint

const (
	UnknownSerialization = Serialization(iota)
	JSON
	CBOR
)

type CMW struct {
	val any
}

func (o *CMW) Deserialize(b []byte) error {
	switch sniff(b) {
	case collection:
		var coll Collection
		if err := coll.Deserialize(b); err != nil {
			return err
		}
		o.val = coll
		return nil
	case leaf:
		var lf Leaf
		lf.Deserialize(b)
		o.val = lf
		return nil
	default:
		return errors.New("unknown CMW type")
	}
}

func (o CMW) Serialize(s Serialization) ([]byte, error) {
	switch v := o.val.(type) {
	case Leaf:
		return v.Serialize(s)
	case Collection:
		return v.Serialize(s)
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

type cmwNodeType uint

const (
	unknownType = cmwNodeType(iota)
	leaf
	collection
)

func sniff(b []byte) cmwNodeType {
	s := sniff_leaf(b)

	if s == UnknownForm {
		if sniff_collection(b) {
			return collection
		}
	} else {
		return leaf
	}

	return unknownType
}
