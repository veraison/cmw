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

	var expectedA CMW
	expectedA.SetMediaType("application/vnd.a")
	expectedA.SetValue([]byte{0x61})
	expectedA.SetSerialization(JSONArray)

	var expectedB CMW
	expectedB.SetMediaType("application/vnd.b")
	expectedB.SetValue([]byte{0x62})
	expectedB.SetSerialization(JSONArray)

	var actual Collection
	err := actual.UnmarshalJSON(tv)
	assert.NoError(t, err)

	a, err := actual.GetItem("a")
	assert.NoError(t, err)
	assert.Equal(t, a, expectedA)

	b, err := actual.GetItem("b")
	assert.NoError(t, err)
	assert.Equal(t, b, expectedB)
}

func Test_Collection_JSON_Serialize_ok(t *testing.T) {
	expected := mustReadFile(t, "testdata/collection-ok.json")

	var tv Collection

	var a CMW
	a.SetMediaType("application/vnd.a")
	a.SetValue([]byte{0x61})
	a.SetSerialization(JSONArray)

	tv.AddItem("a", a)

	var b CMW
	b.SetMediaType("application/vnd.b")
	b.SetValue([]byte{0x62})
	b.SetSerialization(JSONArray)

	tv.AddItem("b", b)

	actual, err := tv.Serialize()
	assert.NoError(t, err)

	assert.JSONEq(t, string(expected), string(actual))
}

func Test_Collection_JSON_Deserialize_fail_outer(t *testing.T) {
	tv := []byte(`;rubbish json;`)

	var actual Collection
	err := actual.UnmarshalJSON(tv)
	assert.EqualError(t, err, `unmarshaling JSON collection: invalid character ';' looking for beginning of value`)
}

func Test_Collection_JSON_Deserialize_fail_inner(t *testing.T) {
	tv := []byte(`{ "a": {} }`)

	var actual Collection
	err := actual.UnmarshalJSON(tv)
	assert.EqualError(t, err, `unmarshaling JSON collection item a: unknown CMW format`)
}

func Test_Collection_CBOR_Deserialize_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-ok.cbor")

	var actual Collection
	err := actual.UnmarshalCBOR(tv)
	assert.NoError(t, err)

	one, err := actual.GetItem(uint64(1))
	assert.NoError(t, err)
	assert.Equal(t, "application/signed-corim+cbor", one.GetType())
	assert.Equal(t, []byte{0xd2, 0x84, 0x43, 0xa1, 0x1, 0x26, 0xa1}, one.GetValue())
	assert.Equal(t, Indicator(3), one.GetIndicator())
	assert.Equal(t, CBORArray, one.GetSerialization())

	two, err := actual.GetItem(uint64(2))
	assert.NoError(t, err)
	assert.Equal(t, "29884", two.GetType()) // TN() mapped CoAP C-F
	assert.Equal(t, []byte{0x23, 0x47, 0xda, 0x55}, two.GetValue())
	assert.Equal(t, Indicator(0), two.GetIndicator())
	assert.Equal(t, CBORTag, two.GetSerialization())

	s, err := actual.GetItem("s")
	assert.NoError(t, err)
	assert.Equal(t, "30001", s.GetType())
	assert.Equal(t, []byte{0x23, 0x47, 0xda, 0x55}, s.GetValue())
	assert.Equal(t, Indicator(0), s.GetIndicator())
	assert.Equal(t, CBORArray, s.GetSerialization())
}

func Test_Collection_CBOR_Serialize_ok(t *testing.T) {
	var item1 CMW
	item1.SetMediaType("application/vnd.1")
	item1.SetValue([]byte{0xde, 0xad, 0xbe, 0xef})
	item1.SetSerialization(CBORArray)

	var tv Collection
	tv.AddItem(uint64(1), item1)

	expected := mustReadFile(t, "testdata/collection-cbor-ok-2.cbor")

	b, err := tv.Serialize()
	assert.NoError(t, err)
	assert.Equal(t, expected, b)
}

func Test_Collection_CBOR_Deserialize_and_iterate(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-mixed-keys.cbor")

	var actual Collection
	err := actual.UnmarshalCBOR(tv)
	assert.NoError(t, err)

	for k := range actual.GetMap() {
		switch v := k.(type) {
		case string:
			assert.Equal(t, "string", v)
		case uint64:
			assert.Equal(t, uint64(1024), v)
		default:
			t.FailNow()
		}
	}
}

func Test_Collection_detectSerialization_fail(t *testing.T) {
	var tv Collection

	var a CMW
	a.SetMediaType("application/vnd.a")
	a.SetValue([]byte{0x61})
	a.SetSerialization(JSONArray)

	tv.AddItem("a", a)

	var b CMW
	b.SetMediaType("application/vnd.b")
	b.SetValue([]byte{0x62})
	b.SetSerialization(CBORArray)

	tv.AddItem("b", b)

	s, err := tv.detectSerialization()
	assert.EqualError(t, err, "CMW collection has items with incompatible serializations")
	assert.Equal(t, UnknownCollectionSerialization, s)
}

func Test_Collection_Deserialize_JSON_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-ok.json")

	var c Collection
	err := c.Deserialize(tv)
	assert.NoError(t, err)
}

func Test_Collection_Deserialize_CBOR_ok(t *testing.T) {
	tv := mustReadFile(t, "testdata/collection-cbor-ok.cbor")

	var c Collection
	err := c.Deserialize(tv)
	assert.NoError(t, err)
}
