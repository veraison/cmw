// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"testing"
)

// Benchmark data generators for different sizes and complexities

func makeSmallMonad() *CMW {
	cmw, _ := NewMonad("application/json", []byte("small test data"), ReferenceValues)
	return cmw
}

func makeMediumMonad() *CMW {
	// Create ~1KB of data
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	cmw, _ := NewMonad("application/cbor", largeData, ReferenceValues, Endorsements)
	return cmw
}

func makeLargeMonad() *CMW {
	// Create ~100KB of data
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	cmw, _ := NewMonad("application/json", largeData, ReferenceValues, Endorsements, Evidence)
	return cmw
}

func makeSimpleCollection() *CMW {
	root, _ := NewCollection("tag:example.com,2024:simple")
	
	node1, _ := NewMonad("application/json", []byte("data1"), ReferenceValues)
	_ = root.AddCollectionItem("item1", node1)
	
	node2, _ := NewMonad("application/cbor", []byte("data2"), Endorsements)
	_ = root.AddCollectionItem("item2", node2)
	
	return root
}

func makeComplexCollection() *CMW {
	// Create a complex nested collection similar to makeCMWCollection but more complex
	root, _ := NewCollection("tag:ietf.org,2024:benchmark")
	
	// Add multiple nested collections
	for i := 0; i < 5; i++ {
		sub, _ := NewCollection("tag:ietf.org,2024:sub")
		
		// Add multiple items to each sub-collection
		for j := 0; j < 10; j++ {
			data := make([]byte, 100+j*10) // Variable sized data
			for k := range data {
				data[k] = byte((i*10 + j + k) % 256)
			}
			
			node, _ := NewMonad("application/cbor", data, ReferenceValues, Endorsements)
			_ = sub.AddCollectionItem(j, node)
		}
		
		_ = root.AddCollectionItem(i, sub)
	}
	
	return root
}

// JSON Marshaling Benchmarks

func BenchmarkCMW_MarshalJSON_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalJSON_MediumMonad(b *testing.B) {
	cmw := makeMediumMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalJSON_LargeMonad(b *testing.B) {
	cmw := makeLargeMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalJSON_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalJSON_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalJSON()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// CBOR Marshaling Benchmarks

func BenchmarkCMW_MarshalCBOR_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalCBOR_MediumMonad(b *testing.B) {
	cmw := makeMediumMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalCBOR_LargeMonad(b *testing.B) {
	cmw := makeLargeMonad()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalCBOR_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalCBOR_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// JSON Unmarshaling Benchmarks

func BenchmarkCMW_UnmarshalJSON_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalJSON_MediumMonad(b *testing.B) {
	cmw := makeMediumMonad()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalJSON_LargeMonad(b *testing.B) {
	cmw := makeLargeMonad()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalJSON_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalJSON_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalJSON(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// CBOR Unmarshaling Benchmarks

func BenchmarkCMW_UnmarshalCBOR_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalCBOR_MediumMonad(b *testing.B) {
	cmw := makeMediumMonad()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalCBOR_LargeMonad(b *testing.B) {
	cmw := makeLargeMonad()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalCBOR_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalCBOR_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Auto-detection Deserialize Benchmarks

func BenchmarkCMW_Deserialize_JSON_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.Deserialize(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_Deserialize_CBOR_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.Deserialize(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_Deserialize_JSON_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.Deserialize(jsonData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_Deserialize_CBOR_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.Deserialize(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Format Detection Benchmarks

func BenchmarkSniff_JSON_Record(b *testing.B) {
	cmw := makeSmallMonad()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = Sniff(jsonData)
	}
}

func BenchmarkSniff_CBOR_Record(b *testing.B) {
	cmw := makeSmallMonad()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = Sniff(cborData)
	}
}

func BenchmarkSniff_JSON_Collection(b *testing.B) {
	cmw := makeSimpleCollection()
	jsonData, _ := cmw.MarshalJSON()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = Sniff(jsonData)
	}
}

func BenchmarkSniff_CBOR_Collection(b *testing.B) {
	cmw := makeSimpleCollection()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = Sniff(cborData)
	}
}

// X.509 Extension Benchmarks

func BenchmarkCMW_EncodeX509Extension_JSON_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.EncodeX509Extension(ChoiceJson, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_EncodeX509Extension_CBOR_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.EncodeX509Extension(ChoiceCbor, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_EncodeX509Extension_JSON_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.EncodeX509Extension(ChoiceJson, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_EncodeX509Extension_CBOR_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.EncodeX509Extension(ChoiceCbor, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_DecodeX509Extension_JSON_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	ext, _ := cmw.EncodeX509Extension(ChoiceJson, false)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := DecodeX509Extension(*ext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_DecodeX509Extension_CBOR_SimpleCollection(b *testing.B) {
	cmw := makeSimpleCollection()
	ext, _ := cmw.EncodeX509Extension(ChoiceCbor, false)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := DecodeX509Extension(*ext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_DecodeX509Extension_JSON_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	ext, _ := cmw.EncodeX509Extension(ChoiceJson, false)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := DecodeX509Extension(*ext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_DecodeX509Extension_CBOR_ComplexCollection(b *testing.B) {
	cmw := makeComplexCollection()
	ext, _ := cmw.EncodeX509Extension(ChoiceCbor, false)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := DecodeX509Extension(*ext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// CBOR Tag Format Benchmarks

func BenchmarkCMW_MarshalCBOR_Tag_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	cmw.UseCBORTagFormat() // Switch to tag format
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_MarshalCBOR_Tag_MediumMonad(b *testing.B) {
	cmw := makeMediumMonad()
	cmw.UseCBORTagFormat() // Switch to tag format
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.MarshalCBOR()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_UnmarshalCBOR_Tag_SmallMonad(b *testing.B) {
	cmw := makeSmallMonad()
	cmw.UseCBORTagFormat()
	cborData, _ := cmw.MarshalCBOR()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var newCMW CMW
		err := newCMW.UnmarshalCBOR(cborData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Collection Operations Benchmarks

func BenchmarkCMW_GetCollectionItem(b *testing.B) {
	cmw := makeComplexCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Access different items to avoid caching effects
		key := i % 5
		_, err := cmw.GetCollectionItem(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_GetCollectionMeta(b *testing.B) {
	cmw := makeComplexCollection()
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := cmw.GetCollectionMeta()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCMW_AddCollectionItem(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		root, _ := NewCollection("tag:ietf.org,2024:benchmark")
		node, _ := NewMonad("application/json", []byte("test data"), ReferenceValues)
		b.StartTimer()
		
		err := root.AddCollectionItem(i, node)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Type and Value Benchmarks

func BenchmarkType_Set_String(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var t Type
		err := t.Set("application/json")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkType_Set_Uint16(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var t Type
		err := t.Set(uint16(50)) // application/json
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValue_Set(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var v Value
		err := v.Set(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}