package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPrivateCodexDeviceChallengeDoesNotPrintOrWrapSecrets(t *testing.T) {
	var printed bytes.Buffer
	var receivedURL, receivedCode string
	options := &LoginOptions{OnCodexDeviceCode: func(url, code string) error {
		receivedURL, receivedCode = url, code
		return nil
	}}
	if err := deliverCodexDeviceChallenge(options, codexDeviceVerificationURL, "PRIVATE-CODE", &printed); err != nil {
		t.Fatal(err)
	}
	if printed.Len() != 0 || receivedURL != codexDeviceVerificationURL || receivedCode != "PRIVATE-CODE" {
		t.Fatal("private callback failed to deliver exactly the transient code without output")
	}
	options.OnCodexDeviceCode = func(string, string) error { return errors.New("PRIVATE-CODE secret provider error") }
	if err := deliverCodexDeviceChallenge(options, codexDeviceVerificationURL, "PRIVATE-CODE", &printed); err == nil || strings.Contains(err.Error(), "PRIVATE-CODE") || strings.Contains(err.Error(), "provider") {
		t.Fatal("callback error exposed private data or was not rejected")
	}
	if printed.Len() != 0 {
		t.Fatal("private callback wrote a code to stdout")
	}
	if err := deliverCodexDeviceChallenge(&LoginOptions{}, codexDeviceVerificationURL, "LEGACY-CODE", &printed); err != nil || !strings.Contains(printed.String(), "LEGACY-CODE") {
		t.Fatal("interactive device login output was not retained")
	}
}

type deviceRoundTripFunc func(*http.Request) (*http.Response, error)

func (f deviceRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCodexDeviceFlowBoundsProviderResponses(t *testing.T) {
	for _, stage := range []string{"challenge", "poll"} {
		t.Run(stage, func(t *testing.T) {
			client := &http.Client{Transport: deviceRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("PRIVATE-BODY", codexDeviceMaxResponseBytes/8)))}, nil
			})}
			var err error
			if stage == "challenge" {
				_, err = requestCodexDeviceUserCode(context.Background(), client)
			} else {
				_, err = pollCodexDeviceToken(context.Background(), client, "private-id", "private-code", time.Millisecond)
			}
			if err == nil || !strings.Contains(err.Error(), "size limit") || strings.Contains(err.Error(), "PRIVATE-BODY") {
				t.Fatal("oversized provider response was not rejected with a fixed message")
			}
		})
	}
}

func TestCodexDeviceCodeRejectsControlCharacters(t *testing.T) {
	for _, code := range []string{"ABCD-EFGH", "a1b2-C3D4"} {
		if !validCodexDeviceCode(code) {
			t.Fatalf("normal device code %q rejected", code)
		}
	}
	for _, code := range []string{"a", "ABCD\nSECRET", "ABCD SECRET", "ABCD/../../", strings.Repeat("A", 65)} {
		if validCodexDeviceCode(code) {
			t.Fatal("malformed device code admitted")
		}
	}
}

func TestCodexLoginDeliversPrivateChallengeBeforePolling(t *testing.T) {
	requests := 0
	auth := &CodexAuthenticator{deviceClient: &http.Client{Transport: deviceRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"device_auth_id":"private-auth-id","user_code":"PRIVATE-CODE"}`))}, nil
	})}}
	delivered := false
	options := &LoginOptions{
		NoBrowser: true,
		Metadata:  map[string]string{codexLoginModeMetadataKey: codexLoginModeDevice},
		OnCodexDeviceCode: func(url, code string) error {
			delivered = url == codexDeviceVerificationURL && code == "PRIVATE-CODE"
			return errors.New("PRIVATE-CODE untrusted error")
		},
	}
	_, err := auth.Login(context.Background(), &config.Config{}, options)
	if !delivered || requests != 1 || err == nil || strings.Contains(err.Error(), "PRIVATE-CODE") {
		t.Fatal("Codex login polled after refused private delivery or leaked the code")
	}
}

func TestPrivateCodexChallengeCannotFallBackToBrowserLogin(t *testing.T) {
	called := false
	_, err := NewCodexAuthenticator().Login(context.Background(), &config.Config{}, &LoginOptions{
		OnCodexDeviceCode: func(string, string) error {
			called = true
			return nil
		},
	})
	if err == nil || called {
		t.Fatal("private device challenge entered a browser login path")
	}
}

func TestPrivateCodexLoginCancelsPollingWithoutPersisting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := 0
	auth := &CodexAuthenticator{deviceClient: &http.Client{Transport: deviceRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"device_auth_id":"private-auth-id","user_code":"PRIVATE-CODE"}`))}, nil
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}}
	delivered := false
	options := &LoginOptions{
		Metadata: map[string]string{codexLoginModeMetadataKey: codexLoginModeDevice},
		OnCodexDeviceCode: func(string, string) error {
			delivered = true
			cancel()
			return nil
		},
	}
	record, err := auth.Login(ctx, &config.Config{}, options)
	if !delivered || record != nil || err == nil || requests != 2 {
		t.Fatal("cancelled private device flow kept polling or returned an auth record")
	}
}
