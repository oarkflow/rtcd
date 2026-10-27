package server

import (
	"errors"
	"net/http"

	"github.com/oarkflow/rtcd/audit"
	"github.com/oarkflow/rtcd/calls"
	"github.com/oarkflow/rtcd/chat"
	"github.com/oarkflow/rtcd/groups"
	"github.com/oarkflow/rtcd/sfu"
)

// apiError is an error with a stable code a client can act on.
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string { return e.Code }

func bad(msg string) error       { return &apiError{http.StatusBadRequest, "invalid", msg} }
func denied(code string) error   { return &apiError{http.StatusForbidden, code, ""} }
func unauth(code string) error   { return &apiError{http.StatusUnauthorized, code, ""} }
func conflict(code string) error { return &apiError{http.StatusConflict, code, ""} }

// classify turns any error into the status, code and message a caller sees.
// The same answer goes out over a WebSocket and over HTTP.
func classify(err error) (status int, code, msg string) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		return ae.Status, ae.Code, ae.Message
	case errors.Is(err, calls.ErrForbidden), errors.Is(err, groups.ErrForbidden):
		return 403, "forbidden", ""
	case errors.Is(err, groups.ErrIDTaken):
		return 409, "id_taken", ""
	case errors.Is(err, chat.ErrStale):
		return 409, "stale_epoch", ""
	case errors.Is(err, chat.ErrRekey):
		return 409, "rekey_required", ""
	case errors.Is(err, chat.ErrConflict):
		return 409, "conflict", err.Error()
	case errors.Is(err, chat.ErrRevoked):
		return 403, "device_revoked", ""
	case errors.Is(err, chat.ErrWindow):
		return 403, "too_late", err.Error()
	case isMissingKeys(err):
		return 409, "members_without_keys", err.Error()
	case errors.Is(err, chat.ErrNotFound):
		return 404, "not_found", ""
	case errors.Is(err, chat.ErrForbidden):
		return 403, "forbidden", ""
	case errors.Is(err, chat.ErrInvalid):
		return 400, "invalid", err.Error()
	case errors.Is(err, chat.ErrLimit):
		return 429, "limit_reached", err.Error()
	case errors.Is(err, chat.ErrState):
		return 409, "wrong_state", ""
	case errors.Is(err, calls.ErrNotFound):
		return 404, "not_found", ""
	case errors.Is(err, calls.ErrInvalid), errors.Is(err, groups.ErrInvalid):
		return 400, "invalid", err.Error()
	case errors.Is(err, groups.ErrLimit):
		return 429, "limit_reached", err.Error()
	case errors.Is(err, calls.ErrState):
		return 409, "call_not_active", ""
	case errors.Is(err, sfu.ErrRoomFull):
		return 429, "room_full", ""
	case errors.Is(err, sfu.ErrNoPeer):
		return 409, "not_in_room", "" // the client should join again
	case errors.Is(err, sfu.ErrNegotiating):
		return 409, "negotiating", "" // answer the server's offer, then retry
	case errors.Is(err, sfu.ErrNoOffer):
		return 409, "no_offer_outstanding", ""
	case errors.Is(err, sfu.ErrBadPrefs):
		return 400, "bad_preferences", ""
	case errors.Is(err, sfu.ErrRecordingDisabled):
		return 404, "recording_disabled", ""
	case errors.Is(err, sfu.ErrDiskFull):
		return 507, "disk_full", ""
	case errors.Is(err, sfu.ErrRecording):
		return 409, "already_recording", ""
	case errors.Is(err, sfu.ErrNotRecording):
		return 409, "not_recording", ""
	case errors.Is(err, sfu.ErrRecordingE2EE):
		return 409, "recording_unavailable_e2ee", ""
	case errors.Is(err, sfu.ErrE2EERequired):
		return 400, "e2ee_required", ""
	case errors.Is(err, audit.ErrBackpressure):
		return 503, "audit_unavailable", ""
	}
	return 503, "unavailable", ""
}

func outcomeOf(status int) string {
	switch {
	case status == 401 || status == 403 || status == 426 || status == 429:
		return audit.Denied
	default:
		return audit.Failed
	}
}

func isMissingKeys(err error) bool {
	var mk *chat.MissingKeys
	return errors.As(err, &mk)
}
