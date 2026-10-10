package cmd

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
)

const (
	controlAddrEnv       = "CLIPROXY_CONTROL_ADDR"
	controlTokenEnv      = "CLIPROXY_CONTROL_TOKEN"
	controlEnrollmentEnv = "CLIPROXY_CONTROL_ENROLLMENT_ENABLED"
	controlKeysEnv       = "CLIPROXY_CONTROL_KEYS_ENABLED"
	controlKeyStoreEnv   = "CLIPROXY_CONTROL_KEY_STORE_DIR"
	sharedInferenceEnv   = "CLIPROXY_SHARED_KEYS_ENABLED"
)

type controlConfig struct {
	addr            string
	token           string
	enrollment      bool
	keys            bool
	keyStoreDir     string
	sharedInference bool
}

func loadControlConfig(lookup func(string) (string, bool), routing *routingObservabilityConfig) (*controlConfig, error) {
	addr, hasAddr := lookup(controlAddrEnv)
	token, hasToken := lookup(controlTokenEnv)
	enrollment, hasEnrollment := lookup(controlEnrollmentEnv)
	keys, hasKeys := lookup(controlKeysEnv)
	keyDir, hasKeyDir := lookup(controlKeyStoreEnv)
	shared, hasShared := lookup(sharedInferenceEnv)
	if hasShared && shared != "true" && shared != "false" {
		return nil, fmt.Errorf("shared inference flag must be true or false")
	}
	if shared == "true" && (!hasAddr || !hasToken) {
		return nil, fmt.Errorf("shared inference requires the reviewed private control configuration")
	}
	if hasEnrollment && enrollment != "true" && enrollment != "false" {
		return nil, fmt.Errorf("private enrollment flag must be true or false")
	}
	if hasKeys && keys != "true" && keys != "false" {
		return nil, fmt.Errorf("private inference-key flag must be true or false")
	}
	if keys == "true" && (!hasAddr || !hasToken || !hasKeyDir || !filepath.IsAbs(keyDir)) || keys != "true" && hasKeyDir {
		return nil, fmt.Errorf("private inference keys require a dedicated existing absolute store and independent control listener")
	}
	if enrollment == "true" && (!hasAddr || !hasToken) {
		return nil, fmt.Errorf("private enrollment requires independent control listener")
	}
	if !hasAddr && !hasToken {
		return nil, nil
	}
	if !hasAddr || !hasToken || routing == nil || len(token) < observabilityMinSecret ||
		token == routing.token || token == string(routing.hmacKey) || addr == routing.addr {
		return nil, fmt.Errorf("private control requires independent credentials and routing observer")
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("private control address must be a literal loopback IP and nonzero port")
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("private control address must be a literal loopback IP and nonzero port")
	}
	return &controlConfig{addr: addr, token: token, enrollment: enrollment == "true", keys: keys == "true", keyStoreDir: keyDir, sharedInference: shared == "true"}, nil
}

func newControlServer(observer *routingobs.Observer, token string, enrollment ...http.Handler) *http.Server {
	var enroll http.Handler
	if len(enrollment) == 1 {
		enroll = enrollment[0]
	}
	return newControlServerWithKeys(observer, token, enroll, nil)
}

func newControlServerWithKeys(observer *routingobs.Observer, token string, enrollment, keys http.Handler) *http.Server {
	handler := observer.ControlHandler(token)
	if enrollment != nil || keys != nil {
		handler = observer.ControlHandlerWithMutations(token, enrollment, keys)
	}
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}
