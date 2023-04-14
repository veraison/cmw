// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_sniff(t *testing.T) {
	tests := []struct {
		name string
		args []byte
		want Serialization
	}{
		{
			"JSON array with CoAP C-F",
			[]byte(`[30001, "3q2-7w"]`),
			JSONArray,
		},
		{
			"JSON array with media type string",
			[]byte(`["application/vnd.intel.sgx", "3q2-7w"]`),
			JSONArray,
		},
		{
			"CBOR array with CoAP C-F",
			// echo "[30001, h'deadbeef']" | diag2cbor.rb | xxd -p -i
			[]byte{0x82, 0x19, 0x75, 0x31, 0x44, 0xde, 0xad, 0xbe, 0xef},
			CBORArray,
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
			CBORArray,
		},
		{
			"CBOR tag",
			// echo "1668576818(h'deadbeef')" | diag2cbor.rb | xxd -p -i
			[]byte{
				0xda, 0x63, 0x74, 0x76, 0x32, 0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			CBORTag,
		},
		{
			"CBOR Tag Intel",
			// echo "60000(h'deadbeef')" | diag2cbor.rb| xxd -i
			[]byte{0xd9, 0xea, 0x60, 0x44, 0xde, 0xad, 0xbe, 0xef},
			CBORTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sniff(tt.args); got != tt.want {
				t.Errorf("[TC: %s] sniff() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

var (
	testIndicator = Indicator(31)
)

func Test_Deserialize_ok(t *testing.T) {
	tests := []struct {
		name string
		tv   []byte
		exp  CMW
	}{
		{
			"JSON array with CoAP C-F",
			[]byte(`[30001, "3q2-7w"]`),
			CMW{
				Type{uint16(30001)},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
			},
		},
		{
			"JSON array with media type string",
			[]byte(`["application/vnd.intel.sgx", "3q2-7w"]`),
			CMW{
				Type{"application/vnd.intel.sgx"},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
			},
		},
		{
			"JSON array with media type string and indicator",
			[]byte(`["application/vnd.intel.sgx", "3q2-7w", 31]`),
			CMW{
				Type{"application/vnd.intel.sgx"},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				testIndicator,
			},
		},
		{
			"CBOR array with CoAP C-F",
			// echo "[30001, h'deadbeef']" | diag2cbor.rb | xxd -p -i
			[]byte{0x82, 0x19, 0x75, 0x31, 0x44, 0xde, 0xad, 0xbe, 0xef},
			CMW{
				Type{uint16(30001)},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
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
			CMW{
				Type{string("application/vnd.intel.sgx")},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
			},
		},
		{
			"CBOR tag",
			// echo "1668576818(h'deadbeef')" | diag2cbor.rb | xxd -p -i
			[]byte{
				0xda, 0x63, 0x74, 0x76, 0x32, 0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			CMW{
				Type{uint64(1668576818)},
				[]byte{0xde, 0xad, 0xbe, 0xef},
				IndicatorNone,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actual CMW

			err := actual.Deserialize(tt.tv)
			assert.NoError(t, err)

			assert.Equal(t, tt.exp, actual)
		})
	}
}

func Test_Serialize_JSONArray_ok(t *testing.T) {
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
			var cmw CMW

			cmw.SetMediaType(tt.tv.typ)
			cmw.SetValue(tt.tv.val)
			cmw.SetIndicators(tt.tv.ind...)

			actual, err := cmw.Serialize(JSONArray)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.exp, string(actual))
		})
	}
}

func Test_Serialize_CBORArray_ok(t *testing.T) {
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
			var cmw CMW

			cmw.SetContentFormat(tt.tv.typ)
			cmw.SetValue(tt.tv.val)
			cmw.SetIndicators(tt.tv.ind...)

			actual, err := cmw.Serialize(CBORArray)
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, actual)
		})
	}
}

func Test_Serialize_CBORTag_ok(t *testing.T) {
	type args struct {
		typ uint64
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
			[]byte{0xd9, 0xc3, 0x50, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			"2",
			args{
				50001,
				[]byte{0xde, 0xad, 0xbe, 0xef},
			},
			[]byte{0xd9, 0xc3, 0x51, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			"3",
			args{
				50002,
				[]byte{0xde, 0xad, 0xbe, 0xef},
			},
			[]byte{0xd9, 0xc3, 0x52, 0x44, 0xde, 0xad, 0xbe, 0xef},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmw CMW

			cmw.SetTagNumber(tt.tv.typ)
			cmw.SetValue(tt.tv.val)

			actual, err := cmw.Serialize(CBORTag)
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, actual)
		})
	}
}

func Test_SettersGetters(t *testing.T) {
	var cmw CMW

	assert.Nil(t, cmw.GetValue())
	assert.Empty(t, cmw.GetType())
	assert.True(t, cmw.GetIndicator().Empty())

	cmw.SetContentFormat(0)
	assert.Equal(t, "text/plain; charset=utf-8", cmw.GetType())

	cmw.SetTagNumber(TnMin + 16)
	assert.Equal(t, `application/cose; cose-type="cose-encrypt0"`, cmw.GetType())

	cmw.SetMediaType("application/eat+cwt")
	assert.Equal(t, "application/eat+cwt", cmw.GetType())

	cmw.SetValue([]byte{0xff})
	assert.Equal(t, []byte{0xff}, cmw.GetValue())
}

func Test_Deserialize_JSONArray_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty JSONArray",
			[]byte(`[]`),
			`wrong number of entries (0) in the CMW array`,
		},
		{
			"missing mandatory field in JSONArray (1)",
			[]byte(`[10000]`),
			`wrong number of entries (1) in the CMW array`,
		},
		{
			"missing mandatory field in JSONArray (2)",
			[]byte(`["3q2-7w"]`),
			`wrong number of entries (1) in the CMW array`,
		},
		{
			"too many entries in JSONArray",
			[]byte(`[10000, "3q2-7w", 1, "EXTRA"]`),
			`wrong number of entries (4) in the CMW array`,
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
			`unknown CMW format`,
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
			err := cmw.Deserialize(tt.tv)
			assert.EqualError(t, err, tt.expectedErr)
		})
	}
}

func Test_Deserialize_CBORArray_ko(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty JSONArray",
			// echo "[]" | diag2cbor.rb | xxd -i
			[]byte{0x80},
			`unknown CMW format`,
		},
		{
			"missing mandatory field in JSONArray (1)",
			// echo "[10000]" | diag2cbor.rb | xxd -i
			[]byte{0x81, 0x19, 0x27, 0x10},
			`unknown CMW format`,
		},
		{
			"too many entries in JSONArray",
			// echo "[1000, h'deadbeef', 1, false]" | diag2cbor.rb | xxd -i
			[]byte{0x84, 0x19, 0x03, 0xe8, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x01, 0xf4},
			`unknown CMW format`,
		},
		{
			"bad type (float) for type",
			// echo "[1000.23, h'deadbeef']" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0xfb, 0x40, 0x8f, 0x41, 0xd7, 0x0a, 0x3d, 0x70, 0xa4,
				0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			`unmarshaling type: cannot unmarshal 1000.230000 into uint16`,
		},
		{
			"overflow for type",
			// echo "[65536, h'deadbeef']" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x44, 0xde, 0xad, 0xbe,
				0xef,
			},
			`unmarshaling type: cannot unmarshal 65536 into uint16`,
		},
		{
			"bad type (float) for value",
			// echo "[65535, 1.2]" | diag2cbor.rb | xxd -i
			[]byte{
				0x82, 0x19, 0xff, 0xff, 0xfb, 0x3f, 0xf3, 0x33, 0x33, 0x33,
				0x33, 0x33, 0x33,
			},
			`unmarshaling value: cannot decode value: cbor: cannot unmarshal primitives into Go value of type []uint8`,
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

func Test_Deserialize_CBORTag(t *testing.T) {
	tests := []struct {
		name        string
		tv          []byte
		expectedErr string
	}{
		{
			"empty CBOR Tag",
			[]byte{0xda, 0x63, 0x74, 0x01, 0x01},
			`unmarshal CMW CBOR Tag bstr-wrapped value: EOF`,
		},
		{
			"bad type (uint) for value",
			// echo "1668546817(1)" | diag2cbor.rb | xxd -i
			[]byte{0xda, 0x63, 0x74, 0x01, 0x01, 0x01},
			`unmarshal CMW CBOR Tag bstr-wrapped value: cbor: cannot unmarshal positive integer into Go value of type []uint8`,
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

func Test_EncodeArray_sanitize_input(t *testing.T) {
	var cmw CMW

	for _, s := range []Serialization{CBORArray, JSONArray} {
		_, err := cmw.Serialize(s)
		assert.EqualError(t, err, "type and value MUST be set in CMW")
	}

	cmw.SetValue([]byte{0xff})

	for _, s := range []Serialization{CBORArray, JSONArray} {
		_, err := cmw.Serialize(s)
		assert.EqualError(t, err, "type and value MUST be set in CMW")
	}

	cmw.SetMediaType("")

	for _, s := range []Serialization{CBORArray, JSONArray} {
		_, err := cmw.Serialize(s)
		assert.EqualError(t, err, "type and value MUST be set in CMW")
	}

	cmw.SetContentFormat(0)

	for _, s := range []Serialization{CBORArray, JSONArray} {
		_, err := cmw.Serialize(s)
		assert.NoError(t, err)
	}
}
