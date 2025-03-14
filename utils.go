package cmw

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
)

func b64uEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func hexDecode(s string) ([]byte, error) {
	// allow a long hex string to be split over multiple lines (with soft or
	// hard tab indentation)
	m := regexp.MustCompile("[ \t\n]")
	s = m.ReplaceAllString(s, "")

	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mustHexDecode(s string) []byte {
	data, err := hexDecode(s)
	if err != nil {
		panic(err)
	}
	return data
}

func startJSONCollection(c byte) bool { return c == 0x7b }
func startJSONRecord(c byte) bool     { return c == 0x5b }
func startCBORCollection(c byte) bool { return c >= 0xa0 && c <= 0xbb || c == 0xbf }
func startCBORRecord(c byte) bool     { return c == 0x82 || c == 0x83 || c == 0x9f }
func startCBORTag(c byte) bool        { return c >= 0xda }
