package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ffuf-online/platform/internal/store"
)

// error codes used across the API.
const (
	CodeBadRequest   = "bad_request"
	CodeValidation   = "validation_error"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeInternal     = "internal_error"
	CodeUnavailable  = "unavailable"
	CodeScopeDenied  = "scope_denied"
)

// APIError is the body of every failure response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details"`
}

type errorEnvelope struct {
	Error APIError `json:"error"`
}

// writeJSON encodes v with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeError emits the canonical error envelope.
func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, errorEnvelope{Error: APIError{Code: code, Message: message, Details: details}})
}

// statusForStore maps store sentinel errors to HTTP responses.
func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound, "resource not found", nil)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, CodeConflict, "resource already exists", nil)
	case errors.Is(err, store.ErrCrossTenant):
		// A cross-tenant write is indistinguishable from a missing resource:
		// never reveal that another tenant owns the id.
		writeError(w, http.StatusNotFound, CodeNotFound, "resource not found", nil)
	default:
		s.log.Error("store error", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "internal error", nil)
	}
}

// listResponse is the paginated envelope: {"items":[],"total":N,"limit":L,"offset":O}.
type listResponse[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func newList[T any](items []T, total, limit, offset int) listResponse[T] {
	if items == nil {
		items = []T{}
	}
	return listResponse[T]{Items: items, Total: total, Limit: limit, Offset: offset}
}
