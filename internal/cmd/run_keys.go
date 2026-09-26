package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

// environmentKeyController is reachable only after the distinct control
// listener's loopback, bearer, and browser-request gates. It never returns a
// key, digest, environment identity, or storage path.
type environmentKeyController struct {
	store *sdkaccess.EnvironmentKeyStore
}

func (c *environmentKeyController) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if c == nil || c.store == nil {
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.URL.Path == routingobs.ControlKeysPath && r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/json" {
			writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var request struct {
			EnvironmentID string `json:"environmentId"`
			Key           string `json:"key"`
		}
		if !readPrivateControlJSON(r.Body, &request) || !sdkaccess.ValidEnvironmentID(request.EnvironmentID) || !sdkaccess.ValidEnvironmentKey(request.Key) {
			writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		revision, err := c.store.Issue(request.EnvironmentID, request.Key)
		if err != nil {
			writeKeyStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(struct {
			Revision uint64 `json:"revision"`
			Active   bool   `json:"active"`
		}{revision, true})
		return
	}
	if !strings.HasPrefix(r.URL.Path, routingobs.ControlKeysPath+"/") {
		writeEnrollmentError(w, http.StatusNotFound, "not_found")
		return
	}
	environment := strings.TrimPrefix(r.URL.Path, routingobs.ControlKeysPath+"/")
	matchedEnvironment, isMatch := strings.CutSuffix(environment, "/match")
	if isMatch {
		environment = matchedEnvironment
	}
	if !sdkaccess.ValidEnvironmentID(environment) {
		writeEnrollmentError(w, http.StatusNotFound, "not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if isMatch {
			writeEnrollmentError(w, http.StatusNotFound, "not_found")
			return
		}
		revision, active, exists, err := c.store.Inspect(environment)
		if err != nil {
			writeKeyStoreError(w, err)
		} else if !exists {
			writeEnrollmentError(w, http.StatusNotFound, "not_found")
		} else {
			_ = json.NewEncoder(w).Encode(struct {
				Revision uint64 `json:"revision"`
				Active   bool   `json:"active"`
			}{revision, active})
		}
	case http.MethodPost:
		if !isMatch || r.Header.Get("Content-Type") != "application/json" {
			writeEnrollmentError(w, http.StatusNotFound, "not_found")
			return
		}
		var request struct {
			Digest string `json:"digest"`
		}
		if !readPrivateControlJSON(r.Body, &request) {
			writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		revision, active, exists, matchesDigest, err := c.store.InspectDigest(environment, request.Digest)
		if err != nil {
			writeKeyStoreError(w, err)
		} else if !exists {
			writeEnrollmentError(w, http.StatusNotFound, "not_found")
		} else {
			_ = json.NewEncoder(w).Encode(struct {
				Revision      uint64 `json:"revision"`
				Active        bool   `json:"active"`
				MatchesDigest bool   `json:"matchesDigest"`
			}{revision, active, matchesDigest})
		}
	case http.MethodDelete:
		if isMatch {
			writeEnrollmentError(w, http.StatusNotFound, "not_found")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var request struct {
			Revision uint64 `json:"revision"`
		}
		if !readPrivateControlJSON(r.Body, &request) || request.Revision == 0 {
			writeEnrollmentError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if err := c.store.Revoke(environment, request.Revision); err != nil {
			writeKeyStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeEnrollmentError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func readPrivateControlJSON(body io.Reader, dst any) bool {
	raw, err := io.ReadAll(io.LimitReader(body, 513))
	if err != nil || len(raw) > 512 {
		return false
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	open, err := check.Token()
	if err != nil || open != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for check.More() {
		field, err := check.Token()
		name, ok := field.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if check.Decode(&value) != nil {
			return false
		}
	}
	closeToken, err := check.Token()
	if err != nil || closeToken != json.Delim('}') || check.Decode(new(any)) != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst) == nil && decoder.Decode(new(any)) == io.EOF
}

func writeKeyStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sdkaccess.ErrEnvironmentKeyConflict):
		writeEnrollmentError(w, http.StatusConflict, "conflict")
	case errors.Is(err, sdkaccess.ErrEnvironmentKeyUncertain):
		writeEnrollmentError(w, http.StatusServiceUnavailable, "commit_uncertain")
	default:
		writeEnrollmentError(w, http.StatusServiceUnavailable, "unavailable")
	}
}
