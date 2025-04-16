package cmw

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestCMW_EncodeX509Extension_JSON(t *testing.T) {
	tv := makeCMWCollection()
	critical := false

	actual, err := tv.EncodeX509Extension(ChoiceJson, critical)
	assert.NoError(t, err)

	// 0 279: SEQUENCE {
	// 	4   8:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 1 35'
	//    14 265:   OCTET STRING, encapsulates {
	//    18 261:     UTF8String
	// 		 :       '{"__cmwc_t":"tag:ietf.org,2024:X","bretwaldadom"'
	// 		 :       ':["application/eat-ucs+cbor","oQo"],"murmurless"'
	// 		 :       ':{"__cmwc_t":"tag:ietf.org,2024:Y","polyscopic":'
	// 		 :       '["application/eat-ucs+json","eyJlYXRfbm9uY2UiOiA'
	// 		 :       'uLi59",8]},"photoelectrograph":["application/eat'
	// 		 :       '-ucs+cbor","gngY",3]}'
	// 		 :     }
	// 		 :   }
	expected := &pkix.Extension{
		Id:       OidExtCmw,
		Critical: critical,
		Value:    mustHexDecode(`0c8201057b225f5f636d77635f74223a227461673a696574662e6f72672c323032343a58222c226272657477616c6461646f6d223a5b226170706c69636174696f6e2f6561742d7563732b63626f72222c226f516f225d2c226d75726d75726c657373223a7b225f5f636d77635f74223a227461673a696574662e6f72672c323032343a59222c22706f6c7973636f706963223a5b226170706c69636174696f6e2f6561742d7563732b6a736f6e222c2265794a6c59585266626d3975593255694f6941754c693539222c385d7d2c2270686f746f656c656374726f6772617068223a5b226170706c69636174696f6e2f6561742d7563732b63626f72222c22676e6759222c335d7d`),
	}

	assert.Equal(t, expected, actual)
}

func TestCMW_EncodeX509Extension_CBOR(t *testing.T) {
	tv := makeCMWCollection()
	critical := false

	actual, err := tv.EncodeX509Extension(ChoiceCbor, critical)
	assert.NoError(t, err)

	// 0 238: SEQUENCE {
	// 	3   8:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 1 35'
	//    13 225:   OCTET STRING, encapsulates {
	//    16 222:     OCTET STRING
	// 		 :       A4 68 5F 5F 63 6D 77 63 5F 74 73 74 61 67 3A 69
	// 		 :       65 74 66 2E 6F 72 67 2C 32 30 32 34 3A 58 6A 6D
	// 		 :       75 72 6D 75 72 6C 65 73 73 A2 68 5F 5F 63 6D 77
	// 		 :       63 5F 74 73 74 61 67 3A 69 65 74 66 2E 6F 72 67
	// 		 :       2C 32 30 32 34 3A 59 6A 70 6F 6C 79 73 63 6F 70
	// 		 :       69 63 83 78 18 61 70 70 6C 69 63 61 74 69 6F 6E
	// 		 :       2F 65 61 74 2D 75 63 73 2B 6A 73 6F 6E 52 7B 22
	// 		 :       65 61 74 5F 6E 6F 6E 63 65 22 3A 20 2E 2E 2E 7D
	// 		 :       08 6C 62 72 65 74 77 61 6C 64 61 64 6F 6D 82 78
	// 		 :       18 61 70 70 6C 69 63 61 74 69 6F 6E 2F 65 61 74
	// 		 :       2D 75 63 73 2B 63 62 6F 72 42 A1 0A 71 70 68 6F
	// 		 :       74 6F 65 6C 65 63 74 72 6F 67 72 61 70 68 83 78
	// 		 :       18 61 70 70 6C 69 63 61 74 69 6F 6E 2F 65 61 74
	// 		 :       2D 75 63 73 2B 63 62 6F 72 43 82 78 18 03
	// 		 :     }
	// 		 :   }
	expected := &pkix.Extension{
		Id:       OidExtCmw,
		Critical: critical,
		Value:    mustHexDecode(`0481dea4685f5f636d77635f74737461673a696574662e6f72672c323032343a586a6d75726d75726c657373a2685f5f636d77635f74737461673a696574662e6f72672c323032343a596a706f6c7973636f7069638378186170706c69636174696f6e2f6561742d7563732b6a736f6e527b226561745f6e6f6e6365223a202e2e2e7d086c6272657477616c6461646f6d8278186170706c69636174696f6e2f6561742d7563732b63626f7242a10a7170686f746f656c656374726f67726170688378186170706c69636174696f6e2f6561742d7563732b63626f724382781803`),
	}

	assert.Equal(t, expected, actual)
}

func Test_CMWDecodeX509Extension_JSON(t *testing.T) {
	tv := pkix.Extension{
		Id:       OidExtCmw,
		Critical: false,
		Value:    mustHexDecode(`0481dea4685f5f636d77635f74737461673a696574662e6f72672c323032343a586a6d75726d75726c657373a2685f5f636d77635f74737461673a696574662e6f72672c323032343a596a706f6c7973636f7069638378186170706c69636174696f6e2f6561742d7563732b6a736f6e527b226561745f6e6f6e6365223a202e2e2e7d086c6272657477616c6461646f6d8278186170706c69636174696f6e2f6561742d7563732b63626f7242a10a7170686f746f656c656374726f67726170688378186170706c69636174696f6e2f6561742d7563732b63626f724382781803`),
	}

	cmw, err := DecodeX509Extension(tv)
	assert.NoError(t, err)

	actual, err := cmw.MarshalJSON()
	assert.NoError(t, err)

	expected := `{"__cmwc_t":"tag:ietf.org,2024:X","bretwaldadom":["application/eat-ucs+cbor","oQo"],"murmurless":{"__cmwc_t":"tag:ietf.org,2024:Y","polyscopic":["application/eat-ucs+json","eyJlYXRfbm9uY2UiOiAuLi59",8]},"photoelectrograph":["application/eat-ucs+cbor","gngY",3]}`

	assert.JSONEq(t, expected, string(actual))
}

func Test_CMWDecodeX509Extension_CBOR(t *testing.T) {
	tv := pkix.Extension{
		Id:       OidExtCmw,
		Critical: false,
		Value:    mustHexDecode(`0481dea4685f5f636d77635f74737461673a696574662e6f72672c323032343a586a6d75726d75726c657373a2685f5f636d77635f74737461673a696574662e6f72672c323032343a596a706f6c7973636f7069638378186170706c69636174696f6e2f6561742d7563732b6a736f6e527b226561745f6e6f6e6365223a202e2e2e7d086c6272657477616c6461646f6d8278186170706c69636174696f6e2f6561742d7563732b63626f7242a10a7170686f746f656c656374726f67726170688378186170706c69636174696f6e2f6561742d7563732b63626f724382781803`),
	}

	cmw, err := DecodeX509Extension(tv)
	assert.NoError(t, err)

	cborCmw, err := cmw.MarshalCBOR()
	assert.NoError(t, err)
	assert.NotNil(t, cborCmw)

	actual, err := cbor.Diagnose(cborCmw)
	assert.NoError(t, err)

	expected := `{"__cmwc_t": "tag:ietf.org,2024:X", "murmurless": {"__cmwc_t": "tag:ietf.org,2024:Y", "polyscopic": ["application/eat-ucs+json", h'7b226561745f6e6f6e6365223a202e2e2e7d', 8]}, "bretwaldadom": ["application/eat-ucs+cbor", h'a10a'], "photoelectrograph": ["application/eat-ucs+cbor", h'827818', 3]}`

	assert.Equal(t, expected, actual)
}
