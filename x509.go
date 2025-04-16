package cmw

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type Choice uint

const (
	ChoiceJson = Choice(iota)
	ChoiceCbor
)

var OidExtCmw = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 35}

func ExtractFromCertificate(c *x509.Certificate) (*CMW, error) {
	return nil, errors.New("TODO")
}

// EncodeX509Extension encodes the target CMW as either JSON or CBOR (according
// to the specified choice), and wraps it in a X509 extension that can be used
// in Certificates, CSRs, or other PKIX data items.
// Unless you really know what you are doing, critical SHOULD be set to false.
func (o CMW) EncodeX509Extension(choice Choice, critical bool) (*pkix.Extension, error) {
	var (
		encodedExtn, serializedCmw []byte
		serializedCmwWrapper       any
		err                        error
	)

	switch choice {
	case ChoiceCbor:
		serializedCmw, err = o.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("CBOR encoding failed: %w", err)
		}
		serializedCmwWrapper = serializedCmw // as OCTET STRING
	case ChoiceJson:
		serializedCmw, err = o.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("JSON encoding failed: %w", err)
		}
		serializedCmwWrapper = string(serializedCmw) // as UTF8String
	default:
		return nil, errors.New("unknown format")
	}

	encodedExtn, err = asn1.Marshal(serializedCmwWrapper)
	if err != nil {
		return nil, fmt.Errorf("ASN.1 encoding failed: %w", err)
	}

	return &pkix.Extension{
		Id:       OidExtCmw,
		Critical: critical,
		Value:    encodedExtn,
	}, nil
}

// DecodeX509Extension extracts and decodes the CMW from the supplied id-pe-cmw
// extension.
func DecodeX509Extension(extn pkix.Extension) (*CMW, error) {
	if !extn.Id.Equal(OidExtCmw) {
		return nil, fmt.Errorf("expecting id-pe-cmw (1.3.6.1.5.5.7.1.35), got %s", extn.Id)
	}

	var (
		serializedCmwWrapper any
		cmw                  CMW
		err                  error
	)

	_, err = asn1.Unmarshal(extn.Value, &serializedCmwWrapper)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling the extension value: %w", err)
	}

	switch t := serializedCmwWrapper.(type) {
	case []byte:
		err = cmw.UnmarshalCBOR(t)
	case string:
		err = cmw.UnmarshalJSON([]byte(t))
	default:
		return nil, fmt.Errorf("expecting OCTET STRING or UTF8String, got %T", t)
	}

	if err != nil {
		return nil, fmt.Errorf("decoding the wrapped CMW: %w", err)
	}

	return &cmw, nil
}
