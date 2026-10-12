package observability

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	ControlHealthPath                = "/v1/control/health"
	ControlStatePath                 = "/v1/control/state"
	ControlEnrollmentPath            = "/v1/control/enrollments"
	ControlKeysPath                  = "/v1/control/keys"
	ControlAccountsPath              = "/v1/control/accounts"
	ControlAccountAuthorizationsPath = "/v1/control/account-authorizations"
)

// ControlHandler exposes only the read-only, credential-free portion of the
// carrot-local control contract. Mutations are intentionally absent until they
// can be backed by independently reviewed durable operations.
func (o *Observer) ControlHandler(token string) http.Handler {
	return o.ControlHandlerWithEnrollment(token, nil)
}

// ControlHandlerWithEnrollment adds an optional private enrollment operation
// after the independent bearer and literal-loopback admission gates. A nil
// handler keeps every mutation path absent.
func (o *Observer) ControlHandlerWithEnrollment(token string, enrollment http.Handler) http.Handler {
	return o.ControlHandlerWithMutations(token, enrollment, nil)
}

// ControlHandlerWithMutations routes only explicitly supplied private handlers
// after the same independent bearer and literal-loopback checks as reads.
func (o *Observer) ControlHandlerWithMutations(token string, enrollment, keys http.Handler) http.Handler {
	return o.ControlHandlerWithAccounts(token, enrollment, keys, nil)
}

func (o *Observer) ControlHandlerWithAccounts(token string, enrollment, keys, accounts http.Handler) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Binding to loopback is not sufficient when a reverse proxy can connect
		// locally. Never treat forwarding headers as proof of a local caller.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			writeFixedJSON(w, http.StatusNotFound, []byte(`{"error":"not_found"}`))
			return
		}
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if o == nil || len(token) < 32 || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeFixedJSON(w, http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`))
			return
		}
		if enrollment != nil && (r.URL.Path == ControlEnrollmentPath || strings.HasPrefix(r.URL.Path, ControlEnrollmentPath+"/")) {
			enrollment.ServeHTTP(w, r)
			return
		}
		if keys != nil && (r.URL.Path == ControlKeysPath || strings.HasPrefix(r.URL.Path, ControlKeysPath+"/")) {
			keys.ServeHTTP(w, r)
			return
		}
		if accounts != nil && (r.URL.Path == ControlAccountsPath || strings.HasPrefix(r.URL.Path, ControlAccountsPath+"/") || r.URL.Path == ControlAccountAuthorizationsPath || strings.HasPrefix(r.URL.Path, ControlAccountAuthorizationsPath+"/")) {
			accounts.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != ControlHealthPath && r.URL.Path != ControlStatePath {
			writeFixedJSON(w, http.StatusNotFound, []byte(`{"error":"not_found"}`))
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeFixedJSON(w, http.StatusMethodNotAllowed, []byte(`{"error":"method_not_allowed"}`))
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeFixedJSON(w, http.StatusBadRequest, []byte(`{"error":"query_not_allowed"}`))
			return
		}
		snapshot := o.Snapshot(time.Now())
		var body []byte
		if r.URL.Path == ControlHealthPath {
			body, err = json.Marshal(snapshot.Health)
		} else {
			body, err = json.Marshal(snapshot)
		}
		if err != nil {
			writeFixedJSON(w, http.StatusServiceUnavailable, []byte(`{"error":"unavailable"}`))
			return
		}
		writeFixedJSON(w, http.StatusOK, body)
	})
}
