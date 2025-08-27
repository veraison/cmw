package cmw

import (
	"crypto/rand"
	"fmt"

	cose "github.com/veraison/go-cose"
)

// SignCBOR produces a signed-cbor-cmw from the target CMW by signing it with
// the supplied cose.Signer.
func (o CMW) SignCBOR(signer cose.Signer) ([]byte, error) {
	msg := cose.NewSignMessage()

	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = signer.Algorithm()
	msg.Headers.Protected[cose.HeaderLabelContentType] = "application/cmw+cbor"

	payload, err := o.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	return cose.Sign1(rand.Reader, signer, msg.Headers, payload, nil)
}

// VerifyCBOR verifies the signed-cbor-cmw using the supplied cose.Verifier.  If
// the signature is succesfully validated and the payload CMW is correctly
// formatted, the CMW target is populated.
func (o *CMW) VerifyCBOR(verifier cose.Verifier, cbor []byte) error {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(cbor); err != nil {
		return fmt.Errorf("CBOR decoding signed-cbor-cmw: %w", err)
	}

	if v, ok := msg.Headers.Protected[cose.HeaderLabelContentType]; ok {
		if v != "application/cmw+cbor" {
			return fmt.Errorf("unexpected content type in signed-cbor-cmw: %v", v)
		}
	} else {
		return fmt.Errorf("missing mandatory cty parameter in signed-cbor-cmw protected headers")
	}

	if _, ok := msg.Headers.Protected[cose.HeaderLabelAlgorithm]; !ok {
		return fmt.Errorf("missing mandatory alg parameter in signed-cbor-cmw protected headers")
	}

	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("signed-cbor-cmw signature verification failed: %w", err)
	}

	if err := o.UnmarshalCBOR(msg.Payload); err != nil {
		return fmt.Errorf("CBOR decoding signed-cbor-cmw payload: %w", err)
	}

	return nil
}
