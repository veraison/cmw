package cmw

import (
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
)

func makeCMWCollection() *CMW {
	sub, _ := NewCollection(("tag:ietf.org,2024:Y"))

	node, _ := NewMonad("application/eat-ucs+json", []byte(`{"eat_nonce": ...}`), AttestationResults)
	_ = sub.AddCollectionItem("polyscopic", node)

	root, _ := NewCollection("tag:ietf.org,2024:X")

	_ = root.AddCollectionItem("murmurless", sub)

	node, _ = NewMonad("application/eat-ucs+cbor", []byte{0xa1, 0x0a})
	_ = root.AddCollectionItem("bretwaldadom", node)

	node, _ = NewMonad("application/eat-ucs+cbor", []byte{0x82, 0x78, 0x18}, ReferenceValues, Endorsements)
	_ = root.AddCollectionItem("photoelectrograph", node)

	// {
	// 	"__cmwc_t": "tag:ietf.org,2024:X",
	// 	"bretwaldadom": [
	// 	  "application/eat-ucs+cbor",
	// 	  "oQo="
	// 	],
	// 	"murmurless": {
	// 	  "__cmwc_t": "tag:ietf.org,2024:Y",
	// 	  "polyscopic": [
	// 		"application/eat-ucs+json",
	// 		"eyJlYXRfbm9uY2UiOiAuLi59",
	// 		8
	// 	  ]
	// 	},
	// 	"photoelectrograph": [
	// 	  "application/eat-ucs+cbor",
	// 	  "gngY",
	// 	  3
	// 	]
	// }

	return root
}

func Example_encode_JSON_collection() {
	root := makeCMWCollection()

	b, err := root.MarshalJSON()
	if err != nil {
		log.Fatalf("marshal to JSON failed: %v", err)
	}

	fmt.Println(string(b))

	// Output:
	// {"__cmwc_t":"tag:ietf.org,2024:X","bretwaldadom":["application/eat-ucs+cbor","oQo"],"murmurless":{"__cmwc_t":"tag:ietf.org,2024:Y","polyscopic":["application/eat-ucs+json","eyJlYXRfbm9uY2UiOiAuLi59",8]},"photoelectrograph":["application/eat-ucs+cbor","gngY",3]}
}

func Example_get_meta() {
	root := makeCMWCollection()

	meta, _ := root.GetCollectionMeta()

	for _, m := range meta {
		fmt.Printf("%s: %s\n", m.Key, m.Kind)
	}

	// Output:
	// bretwaldadom: monad
	// murmurless: collection
	// photoelectrograph: monad
}

func Example_encode_CBOR_collection() {
	root := makeCMWCollection()

	b, err := root.MarshalCBOR()
	if err != nil {
		log.Fatalf("marshal to CBOR failed: %v", err)
	}

	edn, _ := cbor.Diagnose(b)

	fmt.Println(edn)

	// Output:
	// {"__cmwc_t": "tag:ietf.org,2024:X", "murmurless": {"__cmwc_t": "tag:ietf.org,2024:Y", "polyscopic": ["application/eat-ucs+json", h'7b226561745f6e6f6e6365223a202e2e2e7d', 8]}, "bretwaldadom": ["application/eat-ucs+cbor", h'a10a'], "photoelectrograph": ["application/eat-ucs+cbor", h'827818', 3]}
}

func Example_decode_JSON_record() {
	var o CMW

	err := o.UnmarshalJSON([]byte(`[ "application/vnd.example.rats-conceptual-msg", "I0faVQ", 3 ]`))
	if err != nil {
		log.Fatalf("unmarshal JSON record failed: %v", err)
	}

	fmt.Printf("CMW format: %s\n", o.GetFormat())
	actualType, _ := o.GetMonadType()
	fmt.Printf("type: %s\n", actualType)
	actualValue, _ := o.GetMonadValue()
	fmt.Printf("value (hex): %x\n", actualValue)
	actualIndicator, _ := o.GetMonadIndicator()
	fmt.Printf("indicator: %s\n", actualIndicator)

	// Output:
	// CMW format: JSON record
	// type: application/vnd.example.rats-conceptual-msg
	// value (hex): 2347da55
	// indicator: endorsements, reference values
}

func Example_roundtrip_JSON_collection() {
	var o CMW

	ex := []byte(`{
  "bretwaldadom": [
    "application/eat-ucs+cbor",
    "oQo"
  ],
  "__cmwc_t": "tag:ietf.org,2024:X",
  "json-raw": [
    "application/vnd.my.ref-val",
    "e30K"
  ],
  "murmurless": {
    "__cmwc_t": "tag:ietf.org,2024:Y",
    "polyscopic": [
      "application/eat-ucs+json",
      "eyJlYXRfbm9uY2UiOiAuLi59",
      8
    ]
  },
  "photoelectrograph": [
    "application/eat-ucs+cbor",
    "gngY",
    3
  ]
}`)

	err := o.Deserialize(ex)
	if err != nil {
		log.Fatalf("unmarshal JSON collection failed: %v", err)
	}

	b, err := o.MarshalJSON()
	if err != nil {
		log.Fatalf("marshal collection to JSON failed: %v", err)
	}

	fmt.Println(string(b))

	// Output:
	// {"__cmwc_t":"tag:ietf.org,2024:X","bretwaldadom":["application/eat-ucs+cbor","oQo"],"json-raw":["application/vnd.my.ref-val","e30K"],"murmurless":{"__cmwc_t":"tag:ietf.org,2024:Y","polyscopic":["application/eat-ucs+json","eyJlYXRfbm9uY2UiOiAuLi59",8]},"photoelectrograph":["application/eat-ucs+cbor","gngY",3]}
}

func Example_decode_CBOR_record() {
	var o CMW

	b := mustHexDecode(`83781d6170706c69636174696f6e2f7369676e65642d636f72696d2b63626f724dd901f6d28440a044d901f5a04003`)

	if err := o.UnmarshalCBOR(b); err != nil {
		log.Fatalf("unmarshal CBOR record failed: %v", err)
	}

	fmt.Printf("CMW format: %s\n", o.GetFormat())
	actualType, _ := o.GetMonadType()
	fmt.Printf("type: %s\n", actualType)
	actualValue, _ := o.GetMonadValue()
	fmt.Printf("value (hex): %x\n", actualValue)
	actualIndicator, _ := o.GetMonadIndicator()
	fmt.Printf("indicator: %s\n", actualIndicator)

	// Output:
	// CMW format: CBOR record
	// type: application/signed-corim+cbor
	// value (hex): d901f6d28440a044d901f5a040
	// indicator: endorsements, reference values
}
