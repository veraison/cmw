// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	jsonToCborSentinel = "#cmw-j2c-tunnel"
	cborToJsonSentinel = "#cmw-c2j-tunnel"
)

func serializeJsonToCbor(b []byte) ([]byte, error) {
	a := []any{jsonToCborSentinel, b}
	return cbor.Marshal(a)
}

func serializeCborToJson(b []byte) ([]byte, error) {
	a := []any{cborToJsonSentinel, base64.RawURLEncoding.EncodeToString(b)}
	return json.Marshal(a)
}

func deserializeJsonToCbor(b []byte) ([]byte, error) {
	var a []json.RawMessage
	var sentinel, innerCmw string

	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}

	alen := len(a)

	if alen != 2 {
		return nil, fmt.Errorf("wrong number of entries (%d) in JSON-to-CBOR tunnel", alen)
	}

	if err := json.Unmarshal(a[0], sentinel); err != nil {
		return nil, fmt.Errorf("unmarshaling sentinel: %w", err)
	}
	if sentinel != jsonToCborSentinel {
		return nil, fmt.Errorf("wrong JSON-to-CBOR sentinel: %s", sentinel)
	}

	if err := json.Unmarshal(a[1], innerCmw); err != nil {
		return nil, fmt.Errorf("unmarshaling inner CMW: %w", err)
	}

	return base64.RawURLEncoding.DecodeString(innerCmw)
}

func deserializeCborToJson(b []byte) ([]byte, error) {
	var a []cbor.RawMessage
	var sentinel string
	var innerCmw []byte

	if err := cbor.Unmarshal(b, &a); err != nil {
		return nil, err
	}

	alen := len(a)

	if alen != 2 {
		return nil, fmt.Errorf("wrong number of entries (%d) in CBOR-to-JSON tunnel", alen)
	}

	if err := cbor.Unmarshal(a[0], sentinel); err != nil {
		return nil, fmt.Errorf("unmarshaling sentinel: %w", err)
	}
	if sentinel != cborToJsonSentinel {
		return nil, fmt.Errorf("wrong CBOR-to-JSON sentinel: %s", sentinel)
	}

	if err := cbor.Unmarshal(a[1], innerCmw); err != nil {
		return nil, fmt.Errorf("unmarshaling inner CMW: %w", err)
	}

	return innerCmw, nil
}
