// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import "fmt"

const (
	CfMin = uint16(0)
	CfMax = uint16(65024)
)

const (
	TnMin = uint64(1668546817)
	TnMax = uint64(1668612095)
)

// See https://www.rfc-editor.org/rfc/rfc9277.html#section-4.3

// CBOR Tag number from CoAP Content-Format number
func TN(cf uint16) uint64 {
	// No tag numbers are assigned for Content-Format numbers in range
	// [65025, 65535]
	if cf > CfMax {
		// 18446744073709551615	is registered as "Invalid Tag", so it's good as
		// a "nope" return value
		return ^uint64(0)
	}

	cf64 := uint64(cf)

	return TnMin + (cf64/255)*256 + cf64%255
}

// CoAP Content-Format from number CBOR Tag number
func CF(tn uint64) (uint16, error) {
	if tn < TnMin || tn > TnMax {
		return 0, fmt.Errorf("TN %d out of range", tn)
	}

	return uint16((tn-TnMin)*(256/255) - (tn-TnMin)/256), nil
}
