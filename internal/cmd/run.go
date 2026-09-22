// Package cmd provides command-line interface functionality for the CLI Proxy API server.
// It includes authentication flows for various AI service providers, service startup,
// and other command-line operations.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	routingobs "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/observability"
	logrus "github.com/sirupsen/logrus"
)

const (
	observabilityAddrEnv    = "CLIPROXY_OBSERVABILITY_ADDR"
	observabilityTokenEnv   = "CLIPROXY_OBSERVABILITY_TOKEN"
	observabilityHMACKeyEnv = "CLIPROXY_OBSERVABILITY_HMAC_KEY"
	observabilityMinSecret  = 32
)

type routingObservabilityConfig struct {
	addr    string
	token   string
	hmacKey []byte
}

type routingObservabilityRuntime struct {
	listener net.Listener
	server   *http.Server
	observer *routingobs.Observer
}

func loadRoutingObservabilityConfig(lookup func(string) (string, bool)) (*routingObservabilityConfig, error) {
	addr, hasAddr := lookup(observabilityAddrEnv)
	token, hasToken := lookup(observabilityTokenEnv)
	hmacKey, hasHMACKey := lookup(observabilityHMACKeyEnv)
	configured := 0
	for _, present := range []bool{hasAddr, hasToken, hasHMACKey} {
		if present {
			configured++
		}
	}
	if configured == 0 {
		return nil, nil
	}
	if configured != 3 || addr == "" || token == "" || hmacKey == "" {
		return nil, fmt.Errorf("routing observability requires non-empty %s, %s, and %s", observabilityAddrEnv, observabilityTokenEnv, observabilityHMACKeyEnv)
	}
	if len(token) < observabilityMinSecret {
		return nil, fmt.Errorf("%s must be at least %d bytes", observabilityTokenEnv, observabilityMinSecret)
	}
	if len(hmacKey) < observabilityMinSecret {
		return nil, fmt.Errorf("%s must be at least %d bytes", observabilityHMACKeyEnv, observabilityMinSecret)
	}
	if token == hmacKey {
		return nil, fmt.Errorf("%s and %s must be different", observabilityTokenEnv, observabilityHMACKeyEnv)
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%s must be a literal loopback IP and nonzero port", observabilityAddrEnv)
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be a literal loopback IP and nonzero port", observabilityAddrEnv)
	}
	return &routingObservabilityConfig{addr: addr, token: token, hmacKey: []byte(hmacKey)}, nil
}

func newRoutingObservabilityRuntime() (*routingObservabilityRuntime, error) {
	cfg, err := loadRoutingObservabilityConfig(os.LookupEnv)
	if err != nil || cfg == nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("listen for routing observability: %w", err)
	}
	observer := routingobs.NewObserver(cfg.hmacKey, routingobs.DefaultMaxAccounts)
	server := &http.Server{
		Handler:           observer.Handler(cfg.token),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return &routingObservabilityRuntime{listener: listener, server: server, observer: observer}, nil
}

func (r *routingObservabilityRuntime) close() {
	if r != nil && r.listener != nil {
		_ = r.listener.Close()
	}
}

func (r *routingObservabilityRuntime) start(ctx context.Context, cancel context.CancelFunc) <-chan error {
	done := make(chan error, 1)
	serveDone := make(chan error, 1)
	go func() {
		err := r.server.Serve(r.listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		if err != nil {
			cancel()
		}
		serveDone <- err
	}()
	go func() {
		select {
		case err := <-serveDone:
			done <- err
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			shutdownErr := r.server.Shutdown(shutdownCtx)
			shutdownCancel()
			if shutdownErr != nil {
				_ = r.server.Close()
			}
			serveErr := <-serveDone
			if serveErr != nil {
				done <- serveErr
			} else {
				done <- shutdownErr
			}
		}
	}()
	return done
}

func newServiceBuilder(cfg *config.Config, configPath, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) (*cliproxy.Builder, *routingObservabilityRuntime, error) {
	runtime, err := newRoutingObservabilityRuntime()
	if err != nil {
		return nil, nil, err
	}
	builder := cliproxy.NewBuilder().WithConfig(cfg).WithConfigPath(configPath).WithLocalManagementPassword(localPassword)
	if runtime != nil {
		builder = builder.WithCoreAuthHook(runtime.observer).WithRoutingObserver(runtime.observer)
	}
	if host != nil {
		builder = builder.WithPluginHost(host)
	}
	if len(serverOptions) > 0 {
		builder = builder.WithServerOptions(serverOptions...)
	}
	return builder, runtime, nil
}

func runService(ctx context.Context, service *cliproxy.Service, runtime *routingObservabilityRuntime) error {
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	var observabilityDone <-chan error
	if runtime != nil {
		observabilityDone = runtime.start(runCtx, runCancel)
	}
	serviceErr := service.Run(runCtx)
	runCancel()
	if observabilityDone != nil {
		if observabilityErr := <-observabilityDone; observabilityErr != nil {
			return fmt.Errorf("routing observability listener: %w", observabilityErr)
		}
	}
	return serviceErr
}

// StartService builds and runs the proxy service using the exported SDK.
// It creates a new proxy service instance, sets up signal handling for graceful shutdown,
// and starts the service with the provided configuration.
//
// Parameters:
//   - cfg: The application configuration
//   - configPath: The path to the configuration file
//   - localPassword: Optional password accepted for local management requests
func StartService(cfg *config.Config, configPath string, localPassword string) {
	StartServiceWithPluginHost(cfg, configPath, localPassword, nil)
}

// StartServiceWithPluginHost builds and runs the proxy service with a shared plugin host.
func StartServiceWithPluginHost(cfg *config.Config, configPath string, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) {
	builder, observabilityRuntime, err := newServiceBuilder(cfg, configPath, localPassword, host, serverOptions...)
	if err != nil {
		logrus.Errorf("failed to configure proxy service: %v", err)
		return
	}
	if observabilityRuntime != nil {
		defer observabilityRuntime.close()
	}

	ctxSignal, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runCtx := ctxSignal
	if localPassword != "" {
		var keepAliveCancel context.CancelFunc
		runCtx, keepAliveCancel = context.WithCancel(ctxSignal)
		builder = builder.WithServerOptions(api.WithKeepAliveEndpoint(10*time.Second, func() {
			logrus.Warn("keep-alive endpoint idle for 10s, shutting down")
			keepAliveCancel()
		}))
	}

	service, err := builder.Build()
	if err != nil {
		logrus.Errorf("failed to build proxy service: %v", err)
		return
	}

	err = runService(runCtx, service, observabilityRuntime)
	if err != nil && !errors.Is(err, context.Canceled) {
		logrus.Errorf("proxy service exited with error: %v", err)
	}
}

// StartServiceBackground starts the proxy service in a background goroutine
// and returns a cancel function for shutdown and a done channel.
func StartServiceBackground(cfg *config.Config, configPath string, localPassword string) (cancel func(), done <-chan struct{}) {
	return StartServiceBackgroundWithPluginHost(cfg, configPath, localPassword, nil)
}

// StartServiceBackgroundWithPluginHost starts the proxy service with a shared plugin host.
func StartServiceBackgroundWithPluginHost(cfg *config.Config, configPath string, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) (cancel func(), done <-chan struct{}) {
	ctx, cancelFn := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	builder, observabilityRuntime, err := newServiceBuilder(cfg, configPath, localPassword, host, serverOptions...)
	if err != nil {
		logrus.Errorf("failed to configure proxy service: %v", err)
		close(doneCh)
		return cancelFn, doneCh
	}

	service, err := builder.Build()
	if err != nil {
		observabilityRuntime.close()
		logrus.Errorf("failed to build proxy service: %v", err)
		close(doneCh)
		return cancelFn, doneCh
	}

	go func() {
		defer close(doneCh)
		defer observabilityRuntime.close()
		if err := runService(ctx, service, observabilityRuntime); err != nil && !errors.Is(err, context.Canceled) {
			logrus.Errorf("proxy service exited with error: %v", err)
		}
	}()

	return cancelFn, doneCh
}

// WaitForCloudDeploy waits indefinitely for shutdown signals in cloud deploy mode
// when no configuration file is available.
func WaitForCloudDeploy() {
	// Clarify that we are intentionally idle for configuration and not running the API server.
	logrus.Info("Cloud deploy mode: No config found; standing by for configuration. API server is not started. Press Ctrl+C to exit.")

	ctxSignal, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Block until shutdown signal is received
	<-ctxSignal.Done()
	logrus.Info("Cloud deploy mode: Shutdown signal received; exiting")
}
