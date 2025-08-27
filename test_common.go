package cmw

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	cose "github.com/veraison/go-cose"
)

var testES256Key = []byte(`{
	"kty": "EC",
	"crv": "P-256",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	"kid": "1"
}`)

func getCOSESignerAndVerifier(t *testing.T, keyBytes []byte, alg cose.Algorithm) (cose.Signer, cose.Verifier, error) {
	var key map[string]string

	err := json.Unmarshal(keyBytes, &key)
	if err != nil {
		return nil, nil, err
	}

	pkey, err := getKey(key)
	if err != nil {
		return nil, nil, err
	}

	signer, err := cose.NewSigner(alg, pkey)
	if err != nil {
		return nil, nil, err
	}

	verifier, err := cose.NewVerifier(alg, pkey.Public())
	if err != nil {
		return nil, nil, err
	}

	return signer, verifier, nil
}

func getKey(key map[string]string) (crypto.Signer, error) {
	switch key["kty"] {
	case "EC":
		var c elliptic.Curve
		switch key["crv"] {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, errors.New("unsupported EC curve: " + key["crv"])
		}
		pkey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				X:     mustBase64ToBigInt(key["x"]),
				Y:     mustBase64ToBigInt(key["y"]),
				Curve: c,
			},
			D: mustBase64ToBigInt(key["d"]),
		}
		return pkey, nil
	}
	return nil, errors.New("unsupported key type: " + key["kty"])
}

func mustBase64ToBigInt(s string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(val)
}
