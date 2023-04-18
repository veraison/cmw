// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type Value []byte

func (o *Value) Set(v []byte) error {
	*o = v
	return nil
}

func (o Value) IsSet() bool {
	return len(o) != 0
}

func (o *Value) UnmarshalJSON(b []byte) error {
	var (
		v   []byte
		err error
	)

	if v, err = base64.RawURLEncoding.DecodeString(string(b[1 : len(b)-1])); err != nil {
		return fmt.Errorf("cannot base64 url-safe decode: %w", err)
	}

	*o = v

	return nil
}

func (o Value) MarshalJSON() ([]byte, error) {
	s := base64.RawURLEncoding.EncodeToString([]byte(o))
	return json.Marshal(s)
}

func (o *Value) UnmarshalCBOR(b []byte) error {
	var (
		v   []byte
		err error
	)

	if err = cbor.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("cannot decode value: %w", err)
	}

	*o = v

	return nil
}

func (o Value) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal([]byte(o))
}
