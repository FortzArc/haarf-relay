// Package input holds the ingestion sources. M1 ships line-oriented reading
// from an io.Reader (stdin); file_tail, syslog, and otlp_http arrive in M5.
package input

import (
	"bufio"
	"io"
)

// maxLineBytes bounds a single log line (1 MiB). Longer lines are an input
// error, not a reason to buffer unboundedly.
const maxLineBytes = 1 << 20

// ReadLines feeds each newline-delimited line to fn, skipping empty lines.
// It stops on the first fn error or malformed input (e.g. an oversized line)
// and returns that error.
func ReadLines(r io.Reader, fn func(line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return sc.Err()
}
