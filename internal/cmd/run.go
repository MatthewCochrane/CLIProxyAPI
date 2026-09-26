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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
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
	listener        net.Listener
	server          *http.Server
	observer        *routingobs.Observer
	controlListener net.Listener
	enrollment      *enrollmentController
	keyStore        *sdkaccess.EnvironmentKeyStore
	keyAuthDir      string
	controlServer   *http.Server
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

func newRoutingObservabilityRuntime(serviceConfig *config.Config) (*routingObservabilityRuntime, error) {
	cfg, err := loadRoutingObservabilityConfig(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	control, err := loadControlConfig(os.LookupEnv, cfg)
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
	runtime := &routingObservabilityRuntime{listener: listener, server: server, observer: observer}
	if control != nil {
		if control.keys {
			if serviceConfig == nil || !filepath.IsAbs(serviceConfig.AuthDir) ||
				pathContains(control.keyStoreDir, serviceConfig.AuthDir) || pathContains(serviceConfig.AuthDir, control.keyStoreDir) {
				runtime.close()
				return nil, fmt.Errorf("private inference-key store must be separate from the credential directory")
			}
			info, errDir := os.Lstat(serviceConfig.AuthDir)
			if errDir != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !controlAuthDirOwner(info) {
				runtime.close()
				return nil, fmt.Errorf("private inference keys require a private owned auth directory")
			}
			for path := filepath.Clean(serviceConfig.AuthDir); ; path = filepath.Dir(path) {
				entry, errEntry := os.Lstat(path)
				if errEntry != nil || entry.Mode()&os.ModeSymlink != 0 {
					runtime.close()
					return nil, fmt.Errorf("private inference keys require no symlink in auth directory ancestry")
				}
				if filepath.Dir(path) == path {
					break
				}
			}
			runtime.keyStore, err = sdkaccess.NewEnvironmentKeyStore(control.keyStoreDir)
			if err != nil {
				runtime.close()
				return nil, fmt.Errorf("private inference-key store is unavailable")
			}
			runtime.keyAuthDir = serviceConfig.AuthDir
		}
		if control.enrollment {
			if serviceConfig == nil || !filepath.IsAbs(serviceConfig.AuthDir) {
				runtime.close()
				return nil, fmt.Errorf("private enrollment requires an absolute existing auth directory")
			}
			info, errDir := os.Lstat(serviceConfig.AuthDir)
			if errDir != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !controlAuthDirOwner(info) {
				runtime.close()
				return nil, fmt.Errorf("private enrollment requires a private owned auth directory")
			}
			for path := filepath.Clean(serviceConfig.AuthDir); ; path = filepath.Dir(path) {
				entry, errEntry := os.Lstat(path)
				if errEntry != nil || entry.Mode()&os.ModeSymlink != 0 {
					runtime.close()
					return nil, fmt.Errorf("private enrollment requires no symlink in auth directory ancestry")
				}
				if filepath.Dir(path) == path {
					break
				}
			}
			runtime.enrollment = newEnrollmentController(serviceConfig)
		}
		runtime.controlListener, err = net.Listen("tcp", control.addr)
		if err != nil {
			runtime.close()
			return nil, fmt.Errorf("listen for private control: %w", err)
		}
		var enrollmentHandler, keyHandler http.Handler
		if runtime.enrollment != nil {
			enrollmentHandler = http.HandlerFunc(runtime.enrollment.handle)
		}
		if runtime.keyStore != nil {
			keyHandler = http.HandlerFunc((&environmentKeyController{store: runtime.keyStore}).handle)
		}
		if enrollmentHandler != nil || keyHandler != nil {
			runtime.controlServer = newControlServerWithKeys(observer, control.token, enrollmentHandler, keyHandler)
		} else {
			runtime.controlServer = newControlServer(observer, control.token)
		}
	}
	return runtime, nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (r *routingObservabilityRuntime) close() {
	if r != nil && r.enrollment != nil {
		r.enrollment.close()
	}
	if r != nil && r.keyStore != nil {
		_ = r.keyStore.Close()
	}
	if r != nil && r.listener != nil {
		_ = r.listener.Close()
	}
	if r != nil && r.controlListener != nil {
		_ = r.controlListener.Close()
	}
}

func (r *routingObservabilityRuntime) start(ctx context.Context, cancel context.CancelFunc) <-chan error {
	if r.enrollment != nil {
		r.enrollment.bindService(ctx)
		go func() {
			<-ctx.Done()
			r.enrollment.close()
		}()
	}
	done := make(chan error, 1)
	serve := func(server *http.Server, listener net.Listener) <-chan error {
		serveDone := make(chan error, 1)
		result := make(chan error, 1)
		go func() {
			err := server.Serve(listener)
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
				result <- err
			case <-ctx.Done():
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				shutdownErr := server.Shutdown(shutdownCtx)
				shutdownCancel()
				if shutdownErr != nil {
					_ = server.Close()
				}
				serveErr := <-serveDone
				if serveErr != nil {
					result <- serveErr
				} else {
					result <- shutdownErr
				}
			}
		}()
		return result
	}
	primaryDone := serve(r.server, r.listener)
	var controlDone <-chan error
	if r.controlServer != nil {
		controlDone = serve(r.controlServer, r.controlListener)
	}
	go func() {
		primaryErr := <-primaryDone
		cancel()
		if controlDone != nil {
			if controlErr := <-controlDone; primaryErr == nil {
				primaryErr = controlErr
			}
		}
		done <- primaryErr
	}()
	return done
}

func newServiceBuilder(cfg *config.Config, configPath, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) (*cliproxy.Builder, *routingObservabilityRuntime, error) {
	runtime, err := newRoutingObservabilityRuntime(cfg)
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
	if runtime != nil && runtime.keyStore != nil {
		if err := service.PinControlAuthDir(runtime.keyAuthDir); err != nil {
			runtime.close()
			return err
		}
		if err := service.BindEnvironmentKeyStore(runtime.keyStore); err != nil {
			runtime.close()
			return err
		}
	}
	if runtime != nil && runtime.enrollment != nil {
		if err := service.PinControlAuthDir(runtime.enrollment.authDir); err != nil {
			runtime.close()
			return err
		}
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	var observabilityDone <-chan error
	if runtime != nil {
		observabilityDone = runtime.start(runCtx, runCancel)
	}
	serviceErr := service.Run(runCtx)
	if runtime != nil && runtime.enrollment != nil {
		runtime.enrollment.close()
	}
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
