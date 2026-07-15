// Package redact will hold the allowlist engine, scrubbers, and quarantine
// (M2). For now it provides patient-reference pseudonymization, which parsers
// need from day one so raw patient identifiers never enter the pipeline.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// PatientHasher returns an HMAC-SHA256 pseudonymizer keyed with the
// per-deployment salt. It returns nil when the salt is empty: hashing
// without a deployment-specific salt would leave short identifier spaces
// (MRNs) open to dictionary reversal, so the caller must drop the value
// instead.
func PatientHasher(salt string) func(string) string {
	if salt == "" {
		return nil
	}
	key := []byte(salt)
	return func(ref string) string {
		if ref == "" {
			return ""
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(ref))
		return hex.EncodeToString(mac.Sum(nil))
	}
}
