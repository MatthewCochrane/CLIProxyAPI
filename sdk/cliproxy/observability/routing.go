package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const (
	SnapshotPath       = "/v1/routing/snapshot"
	DefaultMaxAccounts = 64
)

type Counters struct {
	Success   uint64 `json:"success"`
	Failure   uint64 `json:"failure"`
	Hit       uint64 `json:"affinityHit"`
	Miss      uint64 `json:"affinityMiss"`
	Rebind    uint64 `json:"affinityRebind"`
	NoSession uint64 `json:"affinityNoSession"`
}

type AccountSnapshot struct {
	Account  string   `json:"account"`
	Counters Counters `json:"counters"`
}

type Snapshot struct {
	SchemaVersion int               `json:"schemaVersion"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	Totals        Counters          `json:"totals"`
	Accounts      []AccountSnapshot `json:"accounts"`
}

// Observer aggregates only fixed outcomes under keyed opaque account handles.
type Observer struct {
	mu          sync.Mutex
	hmacKey     []byte
	maxAccounts int
	totals      Counters
	accounts    map[string]Counters
}

func NewObserver(hmacKey []byte, maxAccounts int) *Observer {
	if maxAccounts <= 0 {
		maxAccounts = DefaultMaxAccounts
	}
	return &Observer{
		hmacKey:     append([]byte(nil), hmacKey...),
		maxAccounts: maxAccounts,
		accounts:    make(map[string]Counters, maxAccounts),
	}
}

func (o *Observer) accountHandle(authID string) string {
	mac := hmac.New(sha256.New, o.hmacKey)
	_, _ = mac.Write([]byte(authID))
	return "acct_" + hex.EncodeToString(mac.Sum(nil))
}

func (o *Observer) update(authID string, update func(*Counters)) {
	if o == nil || authID == "" {
		return
	}
	handle := o.accountHandle(authID)
	o.mu.Lock()
	defer o.mu.Unlock()
	update(&o.totals)
	counters, exists := o.accounts[handle]
	if !exists && len(o.accounts) >= o.maxAccounts {
		return
	}
	update(&counters)
	o.accounts[handle] = counters
}

func (o *Observer) OnAuthRegistered(context.Context, *coreauth.Auth) {}
func (o *Observer) OnAuthUpdated(context.Context, *coreauth.Auth)    {}

func (o *Observer) OnResult(_ context.Context, result coreauth.Result) {
	o.update(result.AuthID, func(c *Counters) {
		if result.Success {
			c.Success++
		} else {
			c.Failure++
		}
	})
}

func (o *Observer) ObserveAffinity(event coreauth.AffinityEvent, authID string) {
	var increment func(*Counters)
	switch event {
	case coreauth.AffinityEventHit:
		increment = func(c *Counters) {
			c.Hit++
		}
	case coreauth.AffinityEventMiss:
		increment = func(c *Counters) {
			c.Miss++
		}
	case coreauth.AffinityEventRebind:
		increment = func(c *Counters) {
			c.Rebind++
		}
	case coreauth.AffinityEventNoSession:
		increment = func(c *Counters) {
			c.NoSession++
		}
	default:
		return
	}
	o.update(authID, increment)
}

func (o *Observer) Snapshot(now time.Time) Snapshot {
	snapshot := Snapshot{SchemaVersion: 1, GeneratedAt: now.UTC(), Accounts: []AccountSnapshot{}}
	if o == nil {
		return snapshot
	}
	o.mu.Lock()
	snapshot.Totals = o.totals
	snapshot.Accounts = make([]AccountSnapshot, 0, len(o.accounts))
	for account, counters := range o.accounts {
		snapshot.Accounts = append(snapshot.Accounts, AccountSnapshot{Account: account, Counters: counters})
	}
	o.mu.Unlock()
	sort.Slice(snapshot.Accounts, func(i, j int) bool { return snapshot.Accounts[i].Account < snapshot.Accounts[j].Account })
	return snapshot
}

func (o *Observer) Handler(token string) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeFixedJSON(w, http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`))
			return
		}
		if r.URL.Path != SnapshotPath {
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
		body, _ := json.Marshal(o.Snapshot(time.Now()))
		writeFixedJSON(w, http.StatusOK, body)
	})
}

func writeFixedJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
