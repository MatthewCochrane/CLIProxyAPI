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

type builderAuthSourceObserver struct {
	source           func() []*coreauth.Auth
	membership       func(string) (uint64, uint64, bool)
	membershipSource func() (uint64, []coreauth.AuthMembership)
}

func (*builderAuthSourceObserver) ObserveAffinity(coreauth.AffinityEvent, string) {}

func (o *builderAuthSourceObserver) SetAuthSource(source func() []*coreauth.Auth) {
	o.source = source
}

func (o *builderAuthSourceObserver) SetAuthSources(
	source func() []*coreauth.Auth,
	membership func(string) (uint64, uint64, bool),
	membershipSource func() (uint64, []coreauth.AuthMembership),
) {
	o.source = source
	o.membership = membership
	o.membershipSource = membershipSource
}

func TestBuilderWiresAuthoritativeAuthSource(t *testing.T) {
	observer := &builderAuthSourceObserver{}
	service, err := NewBuilder().
		WithConfig(&internalconfig.Config{}).
		WithConfigPath(t.TempDir() + "/config.yaml").
		WithRoutingObserver(observer).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if observer.source == nil {
		t.Fatal("routing observer auth source was not installed")
	}
	if observer.membership == nil || observer.membershipSource == nil {
		t.Fatal("routing observer lightweight membership sources were not installed")
	}
	if _, err = service.coreManager.Register(context.Background(), &coreauth.Auth{ID: "current", Status: coreauth.StatusActive}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	auths := observer.source()
	if len(auths) != 1 || auths[0].ID != "current" {
		t.Fatalf("auth source = %#v, want current manager state", auths)
	}
	auths[0].ID = "mutated-clone"
	if current := observer.source(); len(current) != 1 || current[0].ID != "current" {
		t.Fatalf("auth source did not return detached clones: %#v", current)
	}
	generation, epoch, ok := observer.membership("current")
	if !ok || epoch == 0 {
		t.Fatalf("registration epoch = %d/%v, want current nonzero epoch", epoch, ok)
	}
	snapshotGeneration, memberships := observer.membershipSource()
	if generation == 0 || snapshotGeneration != generation {
		t.Fatalf("membership generations exact/snapshot = %d/%d", generation, snapshotGeneration)
	}
	if len(memberships) != 1 || memberships[0].ID != "current" || memberships[0].RegistrationEpoch != epoch {
		t.Fatalf("auth memberships = %#v, want current epoch %d", memberships, epoch)
	}
}

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
