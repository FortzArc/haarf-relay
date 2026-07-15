// Package emit holds the output destinations. M1 ships JSON-lines to an
// io.Writer (stdout); Splunk HEC and OTLP/HTTP with retry queues arrive in M4.
package emit

import (
	"bufio"
	"io"

	"github.com/FortzArc/haarf-relay/internal/event"
)

// Emitter delivers one serialized event to a destination.
type Emitter interface {
	Emit(ev *event.CanonicalEvent) error
	// Flush drains any buffering. Called once at end of input and before
	// shutdown.
	Flush() error
}

// JSONL writes one flat-JSON event per line.
type JSONL struct {
	w *bufio.Writer
}

func NewJSONL(w io.Writer) *JSONL {
	return &JSONL{w: bufio.NewWriter(w)}
}

func (j *JSONL) Emit(ev *event.CanonicalEvent) error {
	b, err := ev.MarshalFlat()
	if err != nil {
		return err
	}
	if _, err := j.w.Write(b); err != nil {
		return err
	}
	return j.w.WriteByte('\n')
}

func (j *JSONL) Flush() error { return j.w.Flush() }
