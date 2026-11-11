// Package jobs signs and verifies worker jobs.
//
// The signature covers the canonical JSON (deterministic key ordering, no
// insignificant whitespace) of the job with its `signature` field cleared. It
// is an HMAC-SHA256, hex encoded, keyed with JOB_SIGNING_SECRET.
package jobs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ffuf-online/platform/internal/domain"
)

// ErrSignatureMissing is returned when a job carries no signature.
var ErrSignatureMissing = errors.New("jobs: job has no signature")

// ErrSignatureInvalid is returned when a job's signature does not verify. The
// job must never be dispatched in that case.
var ErrSignatureInvalid = errors.New("jobs: signature does not verify")

// Sign returns the hex HMAC-SHA256 of the job's canonical JSON with the
// signature field cleared.
func Sign(job domain.Job, secret string) (string, error) {
	clear := job
	clear.Signature = nil
	canonical, err := CanonicalJSON(clear)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Signed returns a copy of job with Signature set.
func Signed(job domain.Job, secret string) (domain.Job, error) {
	sig, err := Sign(job, secret)
	if err != nil {
		return domain.Job{}, err
	}
	out := job
	out.Signature = &sig
	return out, nil
}

// Verify reports whether job's signature is present and valid.
func Verify(job domain.Job, secret string) error {
	if job.Signature == nil || *job.Signature == "" {
		return ErrSignatureMissing
	}
	want, err := Sign(job, secret)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(*job.Signature)) {
		return ErrSignatureInvalid
	}
	return nil
}

// CanonicalJSON renders v with sorted object keys and no insignificant
// whitespace.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jobs: canonical json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("jobs: canonical json: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jobs: canonical json: unsupported type %T", v)
	}
	return nil
}
