// Package server provides attested-client verification for the /pull endpoint.
//
// The verification mirrors example-secret-keys: the caller presents a TLS
// client certificate (forwarded by the proxy as X-Forwarded-Client-Cert, base64
// DER) and an attestation document (Tinfoil-Client-Attestation header). The
// server verifies the SNP/TDX quote, binds the client cert's public key to the
// attested TLS key fingerprint, and optionally checks the code measurement
// against a Sigstore-published release for an allowed repo.
package server

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// clientCertHeader is the standard X-Forwarded-Client-Cert (XFCC) header.
// It carries the base64-encoded DER of the TLS client certificate, forwarded
// by the TLS-terminating proxy (shim, Caddy, Envoy, etc.).
const clientCertHeader = "X-Forwarded-Client-Cert"

// attestationHeader carries the base64-encoded JSON of attestation.Document.
const attestationHeader = "Tinfoil-Client-Attestation"

// AttestationConfig controls how /pull verifies the caller.
type AttestationConfig struct {
	// AllowedRepos is the list of GitHub repos (owner/name) whose published
	// Sigstore attestation measurements are accepted.
	AllowedRepos []string

	// DevSkipCodeMeasurement skips the Sigstore code-measurement check while
	// keeping SNP/TDX quote verification and TLS-key binding. Dev only.
	DevSkipCodeMeasurement bool

	// SigClient is the Sigstore client for code-measurement verification.
	// Nil when DevSkipCodeMeasurement is true.
	SigClient *sigstore.Client
}

// verifyAttestedClient validates that the request comes from an attested
// enclave whose TLS client certificate key is bound to a valid attestation.
// Returns the matched repo name on success.
func verifyAttestedClient(r *http.Request, cfg *AttestationConfig) (string, error) {
	// 1. Extract the client certificate forwarded by the proxy (XFCC header,
	//    base64 DER — standard Envoy/Istio/HAProxy/Caddy convention).
	certB64 := r.Header.Get(clientCertHeader)
	if certB64 == "" {
		return "", fmt.Errorf("no TLS client certificate (missing %s header)", clientCertHeader)
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return "", fmt.Errorf("decoding client cert base64: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parsing client cert: %w", err)
	}

	// 2. Extract and parse the attestation document.
	attB64 := r.Header.Get(attestationHeader)
	if attB64 == "" {
		return "", fmt.Errorf("missing %s header", attestationHeader)
	}

	// 3. SNP/TDX quote verification.
	var doc attestation.Document
	if err := decodeAttestation(attB64, &doc); err != nil {
		return "", fmt.Errorf("parsing attestation: %w", err)
	}
	verification, err := doc.Verify()
	if err != nil {
		return "", fmt.Errorf("attestation verification: %w", err)
	}

	// 4. Bind the live TLS client key to the attested key (REPORTDATA[:32]).
	clientFP, err := attestation.CertPubkeyFP(cert)
	if err != nil {
		return "", fmt.Errorf("computing client cert fingerprint: %w", err)
	}
	if verification.TLSPublicKeyFP != clientFP {
		return "", fmt.Errorf("TLS client key (%s) does not match attested key (%s)", clientFP, verification.TLSPublicKeyFP)
	}
	log.Printf("/pull verify: snp ok, TLS client key bound to attestation")

	// 5. Dev mode: skip Sigstore code-measurement check.
	if cfg.DevSkipCodeMeasurement {
		log.Printf("/pull verify: dev-skip code measurement")
		if len(cfg.AllowedRepos) > 0 {
			return cfg.AllowedRepos[0], nil
		}
		return "verified", nil
	}

	// 6. Production: verify code measurement against Sigstore for allowed repos.
	if cfg.SigClient == nil {
		return "", fmt.Errorf("sigstore client not available for code measurement verification")
	}
	for _, repo := range cfg.AllowedRepos {
		digest, err := github.FetchLatestDigest(repo)
		if err != nil {
			log.Printf("/pull verify: fetching digest for %s: %v", repo, err)
			continue
		}
		sigBundle, err := github.FetchAttestationBundle(repo, digest)
		if err != nil {
			log.Printf("/pull verify: fetching sigstore bundle for %s@%s: %v", repo, digest, err)
			continue
		}
		codeMeasurement, err := cfg.SigClient.VerifyAttestation(sigBundle, repo, digest)
		if err != nil {
			log.Printf("/pull verify: sigstore verify for %s@%s: %v", repo, digest, err)
			continue
		}
		if err := codeMeasurement.Equals(verification.Measurement); err != nil {
			log.Printf("/pull verify: measurement mismatch for %s: %v", repo, err)
			continue
		}
		log.Printf("/pull verify: code/enclave measurements match repo %s", repo)
		return repo, nil
	}
	return "", fmt.Errorf("no allowed repo matched the enclave measurement")
}
