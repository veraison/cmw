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
		want Format
	}{
		{
			"JSON array with CoAP C-F",
			[]byte(`[30001, "3q2-7w"]`),
			FormatJSONRecord,
		},
		{
			"JSON array with media type string",
			[]byte(`["application/vnd.intel.sgx", "3q2-7w"]`),
			FormatJSONRecord,
		},
		{
			"CBOR array with CoAP C-F",
			// echo "[30001, h'deadbeef']" | diag2cbor.rb | xxd -p -i
			[]byte{0x82, 0x19, 0x75, 0x31, 0x44, 0xde, 0xad, 0xbe, 0xef},
			FormatCBORRecord,
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
			FormatCBORRecord,
		},
		{
			"CBOR tag",
			// echo "1668576818(h'deadbeef')" | diag2cbor.rb | xxd -p -i
			[]byte{
				0xda, 0x63, 0x74, 0x76, 0x32, 0x44, 0xde, 0xad, 0xbe, 0xef,
			},
			FormatCBORTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sniff(tt.args); got != tt.want {
				t.Errorf("[TC: %s] sniff() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func Test_NewMonad(t *testing.T) {
	typ := "text/plain; charset=utf-8"
	val := []byte{0xff}
	ind := Indicator(Evidence)

	cmw := NewMonad(typ, val, ind)

	assert.Equal(t, cmw.GetKind(), KindMonad)

	assert.Equal(t, typ, cmw.GetMonadType())
	assert.Equal(t, val, cmw.GetMonadValue())
	assert.Equal(t, ind, cmw.GetMonadIndicator())
}

func Test_Empty(t *testing.T) {
	var cmw CMW

	assert.Equal(t, "", cmw.GetMonadType())
	assert.Equal(t, []byte(nil), cmw.GetMonadValue())
	assert.Equal(t, Indicator(0), cmw.GetMonadIndicator())

	_, err := cmw.MarshalCBOR()
	assert.EqualError(t, err, "type and value MUST be set in CMW")

	_, err = cmw.MarshalJSON()
	assert.EqualError(t, err, "type and value MUST be set in CMW")

	err = cmw.AddCollectionItem("test", nil)
	assert.EqualError(t, err, `want collection, got "unknown"`)
}

func Test_NewCollection(t *testing.T) {
	ctyp := "tag:example.com,2024:composite-attester"

	cmw := NewCollection(ctyp)

	assert.Equal(t, cmw.GetKind(), KindCollection)

	actual, err := cmw.GetCollectionType()
	assert.NoError(t, err)
	assert.Equal(t, ctyp, actual)

	meta, err := cmw.GetCollectionMeta()
	assert.NoError(t, err)
	assert.Equal(t, meta, []Meta(nil))
}

func Test_GetCollectionMeta(t *testing.T) {
	ctyp := "tag:example.com,2024:composite-attester"

	cmw := NewCollection(ctyp)

	monad := NewMonad("text/plain; charset=utf-8", []byte{0xff}, Indicator(Evidence))
	err := cmw.AddCollectionItem("my-monad", monad)
	assert.NoError(t, err)

	sub := NewCollection("tag:example.com,2024:nested-composite-attester")
	err = cmw.AddCollectionItem("my-collection", sub)
	assert.NoError(t, err)

	meta, err := cmw.GetCollectionMeta()
	assert.NoError(t, err)
	assert.Equal(t, meta, []Meta{
		{"my-collection", KindCollection},
		{"my-monad", KindMonad},
	})
}

func Test_GetCollectionGet(t *testing.T) {
	ctyp := "tag:example.com,2024:composite-attester"

	cmw := NewCollection(ctyp)

	monad := NewMonad("text/plain; charset=utf-8", []byte{0xff}, Indicator(Evidence))
	err := cmw.AddCollectionItem("my-monad", monad)
	assert.NoError(t, err)

	sub := NewCollection("tag:example.com,2024:nested-composite-attester")
	err = cmw.AddCollectionItem("my-collection", sub)
	assert.NoError(t, err)

	item1, err := cmw.GetCollectionItem("my-monad")
	assert.NoError(t, err)
	assert.Equal(t, monad, item1)

	item2, err := cmw.GetCollectionItem("my-collection")
	assert.NoError(t, err)
	assert.Equal(t, sub, item2)

	itemNotFound, err := cmw.GetCollectionItem("uh?")
	assert.EqualError(t, err, `item not found for key "uh?"`)
	assert.Nil(t, itemNotFound)
}
