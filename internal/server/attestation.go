package server

import (
	"encoding/base64"
	"encoding/json"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// decodeAttestation decodes a base64-encoded JSON attestation.Document.
func decodeAttestation(b64 string, doc *attestation.Document) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, doc)
}
