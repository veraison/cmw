// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testIndicator = Indicator(31)

func Test_Deserialize_monad_ok(t *testing.T) {
	tests := []struct {
		name string
		tv   []byte
		exp  monad
	}{
		/*
			{
				"JSON array with media type string",
				[]byte(`["application/vnd.intel.sgx", "3q2-7w"]`),
				monad{
					typ:    Type{"application/vnd.intel.sgx"},
					val:    []byte{0xde, 0xad, 0xbe, 0xef},
					ind:    IndicatorNone,
					format: FormatJSONRecord,
				},
			},
			{
				"JSON array with media type string and indicator",
				[]byte(`["application/vnd.intel.sgx", "3q2-7w", 31]`),
				monad{
					Type{"application/vnd.intel.sgx"},
					[]byte{0xde, 0xad, 0xbe, 0xef},
					testIndicator,
					FormatJSONRecord,
				},
			},
			{
				"CBOR array with CoAP C-F",
				// echo "[30001, h'deadbeef']" | diag2cbor.rb | xxd -p -i
				[]byte{0x82, 0x19, 0x75, 0x31, 0x44, 0xde, 0xad, 0xbe, 0xef},
				monad{
					Type{uint16(30001)},
					[]byte{0xde, 0xad, 0xbe, 0xef},
					IndicatorNone,
					FormatCBORRecord,
				},
			},
			{
				"CBOR array with media type string",
				// echo "[\"application/vnd.intel.sgx\", h'deadbeef']" | diag2cbor.rb | xxd -p -i
				[]byte{
					0x82, 0x78, 0x19, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
					0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x6e, 0x64, 0x2e, 0x69,
					0x6e, 0x74, 0x65, 0x6c, 0x2e, 0x73, 0x67, 0x78, 0x44, 0xde,
					0xad, 0xbe, 0xef,
				},
				monad{
					Type{string("application/vnd.intel.sgx")},
					[]byte{0xde, 0xad, 0xbe, 0xef},
					IndicatorNone,
					FormatCBORRecord,
				},
			},
		*/
		{
			"CBOR tag",
			// echo "1668576818(h'deadbeef')" | diag2cbor.rb | xxd -p -i
			[]byte{
				0xda, 0x63, 0x74, 0x76, 0x32, 0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			monad{
				Type{uint64(1668576818)},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
				FormatCBORTag,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual CMW

			err := actual.Deserialize(tt.tv)
			assert.NoError(t, err)

			assert.Equal(t, KindMonad, actual.GetKind())
			assert.Equal(t, tt.exp.format, actual.GetFormat())
			assert.Equal(t, tt.exp, actual.monad)
		})
	}
}

func Test_MarshalJSON_record_ok(t *testing.T) {
	type args struct {
		typ string
		val []byte
		ind []Indicator
	}

	tests := []struct {
		name string
		tv   args
		exp  string
	}{
		{
			"CoRIM w/ rv, endorsements and cots",
			args{
				"application/corim+signed",
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{ReferenceValues, Endorsements, TrustAnchors},
			},
			`[ "application/corim+signed", "3q2-7w", 19 ]`,
		},
		{
			"EAR",
			args{
				`application/eat+cwt; eat_profile="tag:github.com,2023:veraison/ear"`,
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{},
			},
			`[ "application/eat+cwt; eat_profile=\"tag:github.com,2023:veraison/ear\"", "3q2-7w" ]`,
		},
		{
			"EAT-based attestation results",
			args{
				`application/eat+cwt`,
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{AttestationResults},
			},
			`[ "application/eat+cwt", "3q2-7w", 8 ]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmw, err := NewMonad(tt.tv.typ, tt.tv.val, tt.tv.ind...)
			require.NoError(t, err)

			actual, err := cmw.MarshalJSON()
			assert.NoError(t, err)
			assert.JSONEq(t, tt.exp, string(actual))
		})
	}
}

func Test_MarshalCBOR_record_ok(t *testing.T) {
	type args struct {
		typ uint16
		val []byte
		ind []Indicator
	}

	tests := []struct {
		name string
		tv   args
		exp  []byte
	}{
		{
			"CoRIM w/ rv, endorsements and cots",
			args{
				10000,
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{ReferenceValues, Endorsements, TrustAnchors},
			},
			[]byte{0x83, 0x19, 0x27, 0x10, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x13},
		},
		{
			"EAR",
			args{
				10000,
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{},
			},
			[]byte{0x82, 0x19, 0x27, 0x10, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			"EAT-based attestation results",
			args{
				10001,
				[]byte{0xde, 0xad, 0xbe, 0xef},
				[]Indicator{AttestationResults},
			},
			[]byte{0x83, 0x19, 0x27, 0x11, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x08},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmw, err := NewMonad(tt.tv.typ, tt.tv.val, tt.tv.ind...)
			require.NoError(t, err)

			actual, err := cmw.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, actual)
		})
	}
}

func Test_MarshalCBOR_tag_ok(t *testing.T) {
	type args struct {
		typ uint16 // C-F
		val []byte
	}

	tests := []struct {
		name string
		tv   args
		exp  []byte
	}{
		{
			"1",
			args{
				50000,
				[]byte{0xde, 0xad, 0xbe, 0xef},
			},
			// echo "1668597013(h'deadbeef')" | diag2cbor.rb | xxd -i
			[]byte{0xda, 0x63, 0x74, 0xc5, 0x15, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			"2",
			args{
				50001,
				[]byte{0xde, 0xad, 0xbe, 0xef},
			},
			// echo "1668597014(h'deadbeef')" | diag2cbor.rb | xxd -i
			[]byte{0xda, 0x63, 0x74, 0xc5, 0x16, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			"3",
			args{
				50002,
				[]byte{0xde, 0xad, 0xbe, 0xef},
			},
			// echo "1668597015(h'deadbeef')" | diag2cbor.rb | xxd
			[]byte{0xda, 0x63, 0x74, 0xc5, 0x17, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmw, err := NewMonad(tt.tv.typ, tt.tv.val, testIndicator)
			require.NoError(t, err)

			cmw.UseCBORTagFormat()

			actual, err := cmw.MarshalCBOR()
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, actual)
		})
	}
}

func Test_UnmarshalJSON_record_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty FormatJSONRecord",
			[]byte(`[]`),
			`wrong number of entries (0) in the CMW record`,
		},
		{
			"missing mandatory field in FormatJSONRecord (1)",
			[]byte(`[10000]`),
			`wrong number of entries (1) in the CMW record`,
		},
		{
			"missing mandatory field in FormatJSONRecord (2)",
			[]byte(`["3q2-7w"]`),
			`wrong number of entries (1) in the CMW record`,
		},
		{
			"too many entries in FormatJSONRecord",
			[]byte(`[10000, "3q2-7w", 1, "EXTRA"]`),
			`wrong number of entries (4) in the CMW record`,
		},
		{
			"bad type (float) for type",
			[]byte(`[10000.23, "3q2-7w"]`),
			`unmarshaling type: cannot unmarshal 10000.230000 into uint16`,
		},
		{
			"bad type (float) for value",
			[]byte(`[10000, 1.2]`),
			`unmarshaling value: cannot base64 url-safe decode: illegal base64 data at input byte 0`,
		},
		{
			"invalid padded base64 for value",
			[]byte(`[10000, "3q2-7w=="]`),
			`unmarshaling value: cannot base64 url-safe decode: illegal base64 data at input byte 6`,
		},
		{
			"invalid container (object) for CMW",
			[]byte(`{"type": 10000, "value": "3q2-7w=="}`),
			`want JSON object or JSON array start symbols`,
		},
		{
			"bad type (object) for type",
			[]byte(`[ { "type": 10000 }, "3q2-7w" ]`),
			`unmarshaling type: expecting string or uint16, got map[string]interface {}`,
		},
		{
			"bad JSON (missing `]` in array)",
			[]byte(`[10000, "3q2-7w"`),
			`unexpected end of JSON input`,
		},
		{
			"bad indicator",
			[]byte(`[10000, "3q2-7w", "Evidence"]`),
			`unmarshaling indicator: json: cannot unmarshal string into Go value of type cmw.Indicator`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmw CMW
			err := cmw.UnmarshalJSON(tt.tv)
			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}

func Test_UnmarshalCBOR_record_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty CBOR record",
			// echo "[]" | diag2cbor.rb | xxd -i
			[]byte{0x80},
			`want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x80`,
		},
		{
			"missing mandatory field in FormatJSONRecord (1)",
			// echo "[10000]" | diag2cbor.rb | xxd -i
			[]byte{0x81, 0x19, 0x27, 0x10},
			`want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x81`,
		},
		{
			"too many entries in FormatJSONRecord",
			// echo "[1000, h'deadbeef', 1, false]" | diag2cbor.rb | xxd -i
			[]byte{0x84, 0x19, 0x03, 0xe8, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x01, 0xf4},
			`want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x84`,
		},
		{
			"bad type (float) for type",
			// echo "[1000.23, h'deadbeef']" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0xfb, 0x40, 0x8f, 0x41, 0xd7, 0x0a, 0x3d, 0x70, 0xa4,
				0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			`decoding record: unmarshaling type: cannot unmarshal 1000.230000 into uint16`,
		},
		{
			"overflow for type",
			// echo "[65536, h'deadbeef']" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x44, 0xde, 0xad, 0xbe,
				0xef,
			},
			`decoding record: unmarshaling type: cannot unmarshal 65536 into uint16`,
		},
		{
			"bad type (float) for value",
			// echo "[65535, 1.2]" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0x19, 0xff, 0xff, 0xfb, 0x3f, 0xf3, 0x33, 0x33, 0x33,
				0x33, 0x33, 0x33,
			},
			`decoding record: unmarshaling value: cannot decode value: cbor: cannot unmarshal primitives into Go value of type []uint8`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmw CMW
			err := cmw.UnmarshalCBOR(tt.tv)
			assert.EqualError(t, err, tt.expectedErr)
		})
	}
}

func Test_UnmarshalCBOR_tag_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty CBOR Tag",
			[]byte{0xda, 0x63, 0x74, 0x01, 0x01},
			`decoding tag: unmarshal CMW CBOR Tag bstr-wrapped value: EOF`,
		},
		{
			"bad type (uint) for value",
			// echo "1668546817(1)" | diag2cbor.rb | xxd -i
			[]byte{0xda, 0x63, 0x74, 0x01, 0x01, 0x01},
			`decoding tag: unmarshal CMW CBOR Tag bstr-wrapped value: cbor: cannot unmarshal positive integer into Go value of type []uint8`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmw CMW
			err := cmw.Deserialize(tt.tv)
			assert.EqualError(t, err, tt.expectedErr)
		})
	}
}

func Test_UnmarshalCBOR_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"weird",
			[]byte{0x00},
			"want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x00",
		},
		{
			"empty",
			[]byte{},
			"empty buffer",
		},
		{
			"abruptly truncated collection",
			[]byte{0xa1, 0x00},
			"unmarshaling CBOR collection: unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmw CMW
			err := cmw.UnmarshalCBOR(tt.tv)
			assert.EqualError(t, err, tt.expectedErr)
		})
	}
}

func Test_NewMonad_fail_bad_value(t *testing.T) {
	_, err := NewMonad("application/vnd.example.evidence", nil)
	assert.EqualError(t, err, `empty value`)
}

func Test_NewMonad_fail_bad_mediatype(t *testing.T) {
	_, err := NewMonad("application/ vnd.example.evidence", []byte{0x00})
	assert.EqualError(t, err, `bad media type: mime: expected token after slash`)
}

func Test_NewMonad_fail_bad_type(t *testing.T) {
	_, err := NewMonad(0xffffffff, []byte{0x00})
	assert.EqualError(t, err, `unsupported type int for CMW type`)
}
