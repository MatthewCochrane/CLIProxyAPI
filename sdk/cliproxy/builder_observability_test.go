package cliproxy

import (
	"context"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type builderTestHook struct{}

func (*builderTestHook) OnAuthRegistered(context.Context, *coreauth.Auth) {}
func (*builderTestHook) OnAuthUpdated(context.Context, *coreauth.Auth)    {}
func (*builderTestHook) OnResult(context.Context, coreauth.Result)        {}

func TestBuilderRejectsObserverOptionsWithInjectedCoreManager(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Builder)
	}{
		{name: "core auth hook", configure: func(builder *Builder) { builder.WithCoreAuthHook(&builderTestHook{}) }},
		{name: "routing observer", configure: func(builder *Builder) { builder.WithRoutingObserver(&reloadAffinityObserver{}) }},
		{name: "both", configure: func(builder *Builder) {
			builder.WithCoreAuthHook(&builderTestHook{}).WithRoutingObserver(&reloadAffinityObserver{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewBuilder().
				WithConfig(&internalconfig.Config{}).
				WithConfigPath(t.TempDir() + "/config.yaml").
				WithCoreAuthManager(coreauth.NewManager(nil, nil, nil))
			tt.configure(builder)
			service, err := builder.Build()
			if err == nil || !strings.Contains(err.Error(), "WithCoreAuthManager cannot be combined with WithCoreAuthHook or WithRoutingObserver") {
				t.Fatalf("Build() error = %v, want observer conflict", err)
			}
			if service != nil {
				t.Fatal("Build() returned a service for conflicting core manager options")
			}
		})
	}
}
