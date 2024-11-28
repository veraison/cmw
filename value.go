// Copyright 2023-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"errors"
	"fmt"
)

type Value []byte

func (o *Value) Set(v []byte) error {
	if len(v) == 0 {
		return errors.New("empty value")
	}
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

	if v, err = b64uDecode(string(b[1 : len(b)-1])); err != nil {
		return fmt.Errorf("cannot base64 url-safe decode: %w", err)
	}

	*o = v

	return nil
}

func (o Value) MarshalJSON() ([]byte, error) {
	s := b64uEncode([]byte(o))
	return json.Marshal(s)
}

func (o *Value) UnmarshalCBOR(b []byte) error {
	var (
		v   []byte
		err error
	)

	if err = dm.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("cannot decode value: %w", err)
	}

	*o = v

	return nil
}

func (o Value) MarshalCBOR() ([]byte, error) {
	return em.Marshal([]byte(o))
}
