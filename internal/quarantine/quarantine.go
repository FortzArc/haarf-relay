// Package quarantine is the fail-closed spool: events that fail parsing or
// redaction are by definition possibly-PHI-bearing, so they are written
// age/X25519-encrypted, one file per event, never forwarded and never stored
// in plaintext.
//
// The relay only holds the *recipient* (public key) — quarantine is
// write-only from the relay's perspective; review requires the operator's
// identity (private key), which never lives on the relay host.
package quarantine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/oklog/ulid/v2"
)

// Envelope is the plaintext structure inside each encrypted spool file.
type Envelope struct {
	Reason     string    `json:"reason"`
	ReceivedAt time.Time `json:"received_at"`
	// LineB64 is the original raw input line (base64: it may be arbitrary
	// bytes, and it is exactly what failed to parse or redact).
	LineB64 string `json:"line_b64"`
}

func (e *Envelope) Line() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.LineB64)
}

// Writer spools events into dir, encrypted to recipient.
type Writer struct {
	dir       string
	recipient age.Recipient
	now       func() time.Time
}

// New validates the directory and recipient at construction — a relay that
// cannot quarantine must find out at boot, not on the first bad event.
func New(dir, recipientStr string) (*Writer, error) {
	if dir == "" {
		return nil, fmt.Errorf("quarantine dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("quarantine dir: %w", err)
	}
	rec, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		return nil, fmt.Errorf("quarantine recipient (want an age1... public key): %w", err)
	}
	return &Writer{dir: dir, recipient: rec, now: time.Now}, nil
}

// Write spools one event. The write is crash-safe: encrypt to a temp file,
// sync, then rename into place — a torn file never carries the .age name.
func (w *Writer) Write(reason string, line []byte) error {
	env := Envelope{
		Reason:     reason,
		ReceivedAt: w.now().UTC(),
		LineB64:    base64.StdEncoding.EncodeToString(line),
	}
	name := ulid.MustNew(ulid.Now(), rand.Reader).String() + ".age"
	tmp := filepath.Join(w.dir, name+".tmp")

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // no-op after successful rename

	enc, err := age.Encrypt(f, w.recipient)
	if err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(enc).Encode(&env); err != nil {
		f.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(w.dir, name))
}

// Decrypt opens one spool file with the operator's identity — the review
// path (and the conformance suite's proof that spools are recoverable).
func Decrypt(path string, identity age.Identity) (*Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
