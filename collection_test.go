// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustReadFile(t *testing.T, fname string) []byte {
	b, err := os.ReadFile(fname)
	require.NoError(t, err)
	return b
}

func Test_Collection_JSON_Deserialize_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-ok.json")

	var actual CMW
	err := actual.UnmarshalJSON(tv)
	assert.NoError(t, err)

	assert.Equal(t, actual.GetFormat().String(), "JSON collection")

	a, err := actual.GetCollectionItem("a")
	assert.NoError(t, err)
	assert.Equal(t, FormatJSONRecord, a.GetFormat())
	assert.Equal(t, KindMonad, a.GetKind())
	actualType, _ := a.GetMonadType()
	assert.Equal(t, "application/vnd.a", actualType)
	actualValue, _ := a.GetMonadValue()
	assert.Equal(t, []byte{0x61}, actualValue)
	actualIndicator, _ := a.GetMonadIndicator()
	assert.Equal(t, Indicator(0), actualIndicator)

	b, err := actual.GetCollectionItem("b")
	assert.NoError(t, err)
	assert.Equal(t, FormatJSONRecord, b.GetFormat())
	assert.Equal(t, KindMonad, b.GetKind())
	actualType, _ = b.GetMonadType()
	assert.Equal(t, "application/vnd.b", actualType)
	actualValue, _ = b.GetMonadValue()
	assert.Equal(t, []byte{0x62}, actualValue)
	actualIndicator, _ = b.GetMonadIndicator()
	assert.Equal(t, Indicator(0), actualIndicator)
}

func Test_Collection_JSON_Serialize_ok(t *testing.T) {
	expected := mustReadFile(t, "testdata/collection-ok.json")

	tv, err := NewCollection("")
	require.NoError(t, err)

	a, err := NewMonad("application/vnd.a", []byte{0x61})
	require.NoError(t, err)

	err = tv.AddCollectionItem("a", a)
	require.NoError(t, err)

	b, err := NewMonad("application/vnd.b", []byte{0x62})
	require.NoError(t, err)

	err = tv.AddCollectionItem("b", b)
	require.NoError(t, err)

	actual, err := tv.MarshalJSON()
	assert.NoError(t, err)

	assert.JSONEq(t, string(expected), string(actual))
}

func Test_Collection_JSON_Deserialize_fail_inner(t *testing.T) {
	tv := []byte(`{ "a": { "__cmwc_t": "1.2.3.4" } }`)

	var actual CMW
	err := actual.UnmarshalJSON(tv)
	require.NoError(t, err)
	err = actual.ValidateCollection()
	assert.EqualError(t, err, `invalid collection at key "a": empty CMW collection`)
}

func Test_Collection_CBOR_Deserialize_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-ok.cbor")

	var actual CMW
	err := actual.UnmarshalCBOR(tv)
	assert.NoError(t, err)

	assert.Equal(t, actual.GetFormat().String(), "CBOR collection")

	one, err := actual.GetCollectionItem(uint64(1))
	assert.NoError(t, err)
	assert.Equal(t, KindMonad, one.GetKind())
	assert.Equal(t, FormatCBORRecord, one.GetFormat())
	actualType, _ := one.GetMonadType()
	assert.Equal(t, "application/signed-corim+cbor", actualType)
	actualValue, _ := one.GetMonadValue()
	assert.Equal(t, []byte{0xd2, 0x84, 0x43, 0xa1, 0x1, 0x26, 0xa1}, actualValue)
	actualIndicator, _ := one.GetMonadIndicator()
	assert.Equal(t, Indicator(3), actualIndicator)

	two, err := actual.GetCollectionItem(uint64(2))
	assert.NoError(t, err)
	assert.Equal(t, KindMonad, two.GetKind())
	assert.Equal(t, FormatCBORTag, two.GetFormat())
	actualType, _ = two.GetMonadType()
	assert.Equal(t, "29884", actualType) // TN() mapped CoAP C-F
	actualValue, _ = two.GetMonadValue()
	assert.Equal(t, []byte{0x23, 0x47, 0xda, 0x55}, actualValue)
	actualIndicator, _ = two.GetMonadIndicator()
	assert.Equal(t, Indicator(0), actualIndicator)

	s, err := actual.GetCollectionItem("s")
	assert.NoError(t, err)
	assert.Equal(t, KindMonad, s.GetKind())
	assert.Equal(t, FormatCBORRecord, s.GetFormat())
	actualType, _ = s.GetMonadType()
	assert.Equal(t, "30001", actualType)
	actualValue, _ = s.GetMonadValue()
	assert.Equal(t, []byte{0x23, 0x47, 0xda, 0x55}, actualValue)
	actualIndicator, _ = s.GetMonadIndicator()
	assert.Equal(t, Indicator(0), actualIndicator)
}

func Test_Collection_CBOR_Serialize_ok(t *testing.T) {
	expected := mustReadFile(t, "testdata/collection-cbor-ok-2.cbor")

	item1, err := NewMonad("application/vnd.1", []byte{0xde, 0xad, 0xbe, 0xef})
	require.NoError(t, err)

	tv, err := NewCollection("")
	require.NoError(t, err)

	err = tv.AddCollectionItem(uint64(1), item1)
	require.NoError(t, err)

	b, err := tv.MarshalCBOR()
	assert.NoError(t, err)
	assert.Equal(t, expected, b)
}

func Test_Collection_CBOR_Deserialize_and_iterate(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-mixed-keys.cbor")

	var actual CMW
	err := actual.UnmarshalCBOR(tv)
	require.NoError(t, err)
	require.Equal(t, KindCollection, actual.GetKind())

	meta, err := actual.GetCollectionMeta()
	require.NoError(t, err)

	for _, m := range meta {
		switch v := m.Key.(type) {
		case string:
			assert.Equal(t, "string", v)
		case uint64:
			assert.Equal(t, uint64(1024), v)
		default:
			t.FailNow()
		}
	}
}

func Test_Collection_Deserialize_JSON_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-ok.json")

	var c CMW
	err := c.Deserialize(tv)
	assert.NoError(t, err)
	assert.Equal(t, KindCollection, c.GetKind())
	assert.Equal(t, FormatJSONCollection, c.GetFormat())
}

func Test_Collection_Deserialize_CBOR_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-ok.cbor")

	var c CMW
	err := c.Deserialize(tv)
	assert.NoError(t, err)
	assert.Equal(t, KindCollection, c.GetKind())
	assert.Equal(t, FormatCBORCollection, c.GetFormat())
}

func Test_isValidCollectionType(t *testing.T) {
	type args struct {
		ctyp string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// valid
		{"tag URI", args{`tag:example.com,2024:composite-attester`}, false},
		{"urn URI", args{`urn:ietf:rfc:rfc9999`}, false},
		{"http URI", args{`http://www.ietf.org/rfc/rfc2396.txt`}, false},
		{"absolute OID", args{`1.2.3.4`}, false},
		// invalid
		{"(empty) relative URI", args{``}, true},
		{"relative URI", args{`a/b/c`}, true},
		{"relative OID", args{`.2.3.4`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCollectionType(tt.args.ctyp); (err != nil) != tt.wantErr {
				t.Errorf("isValidCollectionType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_isValidCollectionKey(t *testing.T) {
	type args struct {
		key any
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// valid
		{"ok-string-label", args{`my-label`}, false},
		{"ok-uint-label", args{uint64(1)}, false},
		{"ok-int-label", args{int64(1)}, false},
		// invalid
		{"empty-label", args{``}, true},
		{"whitespace-only-label", args{`   `}, true},
		{"bad-type-for-label", args{float32(1.0)}, true},
		{"reserved-for-cmwc_t", args{`__cmwc_t`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCollectionKey(tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("isValidCollectionKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_AddCollectionItem_ko(t *testing.T) {
	c, err := NewCollection("1.2.3.4")
	require.NoError(t, err)

	err = c.AddCollectionItem("key", nil)

	assert.EqualError(t, err, "nil node")
}

func Test_NewCollection_fail_bad_cmwc_t(t *testing.T) {
	_, err := NewCollection("1.2 3.4")
	assert.EqualError(t, err, `invalid collection type: "1.2 3.4".  URI is not absolute`)
}
