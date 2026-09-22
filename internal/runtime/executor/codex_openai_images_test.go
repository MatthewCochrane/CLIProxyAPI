package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func newCodexOpenAIImageTestAuth(serverURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"base_url": serverURL,
			"api_key":  "codex-token",
		},
	}
}

func codexOpenAIImageTestOptions(path string, stream bool) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString(codexOpenAIImageSourceFormat),
		Stream:       stream,
		Metadata: map[string]any{
			cliproxyexecutor.RequestPathMetadataKey: path,
		},
	}
}

func TestCodexExecutorOpenAIImageResponsesNonStreamHeaderTimeout(t *testing.T) {
	cfg := codexImageTimeoutTestConfig("30ms", "1s", "1s")
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	executor := NewCodexExecutor(cfg)
	_, err := executor.Execute(ctx, newCodexOpenAIImageTestAuth("https://images.private.test"), codexImageTimeoutTestRequest("dall-e-3"), codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
	assertCodexImageTimeout(t, err, helps.ErrCodexResponseHeaderTimeout)
}

func TestCodexExecutorOpenAIImageResponsesStreamIdleTimeout(t *testing.T) {
	cfg := codexImageTimeoutTestConfig("1s", "30ms", "1s")
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return codexImageTimeoutResponse(&codexImageWaitBody{ctx: req.Context()}), nil
	}))
	executor := NewCodexExecutor(cfg)
	result, err := executor.ExecuteStream(ctx, newCodexOpenAIImageTestAuth("https://images.private.test"), codexImageTimeoutTestRequest("dall-e-3"), codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	assertCodexImageTimeout(t, codexImageStreamError(result), helps.ErrCodexStreamIdleTimeout)
}

func TestCodexExecutorDirectOpenAIImageNonStreamTotalTimeout(t *testing.T) {
	cfg := codexImageTimeoutTestConfig("1s", "200ms", "50ms")
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return codexImageTimeoutResponse(&codexImagePacedBody{ctx: req.Context()}), nil
	}))
	executor := NewCodexExecutor(cfg)
	_, err := executor.Execute(ctx, newCodexOpenAIImageTestAuth("https://images.private.test"), codexImageTimeoutTestRequest("gpt-image-1.5"), codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
	assertCodexImageTimeout(t, err, helps.ErrCodexTotalTimeout)
}

func TestCodexExecutorDirectOpenAIImageStreamIdleTimeout(t *testing.T) {
	cfg := codexImageTimeoutTestConfig("1s", "30ms", "1s")
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return codexImageTimeoutResponse(&codexImageWaitBody{ctx: req.Context()}), nil
	}))
	executor := NewCodexExecutor(cfg)
	result, err := executor.ExecuteStream(ctx, newCodexOpenAIImageTestAuth("https://images.private.test"), codexImageTimeoutTestRequest("gpt-image-1.5"), codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	assertCodexImageTimeout(t, codexImageStreamError(result), helps.ErrCodexStreamIdleTimeout)
}

func TestCodexExecutorOpenAIImageStandardTransportConnectTimeoutFallsBackWithoutCooling(t *testing.T) {
	var successfulRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		successfulRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}]}`))
	}))
	defer server.Close()

	dialStarted := make(chan struct{}, 1)
	releaseDial := make(chan struct{})
	defer close(releaseDial)
	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.Contains(addr, "connect-timeout.invalid") {
			select {
			case dialStarted <- struct{}{}:
			default:
			}
			<-releaseDial
			return nil, errors.New("test connection attempt released")
		}
		return dialer.DialContext(ctx, network, addr)
	}}
	defer transport.CloseIdleConnections()
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", transport)

	cfg := &config.Config{Codex: config.CodexConfig{HTTPTimeouts: config.CodexHTTPTimeoutConfig{
		Connect: "40ms", ResponseHeader: "1s", StreamIdle: "1s", Total: "1s",
	}}}
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetRetryConfig(0, 0, 0)
	model := "gpt-image-1.5"
	firstID := fmt.Sprintf("%s-first", t.Name())
	executor := &codexImageRecordingExecutor{CodexExecutor: NewCodexExecutor(cfg), firstAuthID: firstID}
	manager.RegisterExecutor(executor)
	auths := []*cliproxyauth.Auth{
		{ID: firstID, Provider: "codex", Status: cliproxyauth.StatusActive, Attributes: map[string]string{"api_key": "first", "base_url": "http://connect-timeout.invalid", "priority": "10"}},
		{ID: fmt.Sprintf("%s-second", t.Name()), Provider: "codex", Status: cliproxyauth.StatusActive, Attributes: map[string]string{"api_key": "second", "base_url": server.URL, "priority": "1"}},
	}
	for _, auth := range auths {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
		if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}

	resp, errExecute := manager.Execute(ctx, []string{"codex"}, codexImageTimeoutTestRequest(model), codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !gjson.GetBytes(resp.Payload, "data.0.b64_json").Exists() || successfulRequests.Load() != 1 {
		t.Fatalf("response = %s, successful requests = %d", resp.Payload, successfulRequests.Load())
	}
	if executor.firstErr == nil || !errors.Is(executor.firstErr, helps.ErrCodexConnectTimeout) || executor.firstErr.Error() != helps.ErrCodexConnectTimeout.Error() {
		t.Fatalf("first credential error = %v, want fixed %v", executor.firstErr, helps.ErrCodexConnectTimeout)
	}
	select {
	case <-dialStarted:
	default:
		t.Fatal("standard transport did not make the timed connection attempt")
	}
	first, ok := manager.GetByID(firstID)
	if !ok || first.Unavailable || !first.NextRetryAfter.IsZero() {
		t.Fatalf("first credential cooled: found=%t unavailable=%t next-retry=%v", ok, first.Unavailable, first.NextRetryAfter)
	}
}

type codexImageRecordingExecutor struct {
	*CodexExecutor
	firstAuthID string
	firstErr    error
}

func (e *codexImageRecordingExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	resp, err := e.CodexExecutor.Execute(ctx, auth, req, opts)
	if auth.ID == e.firstAuthID {
		e.firstErr = err
	}
	return resp, err
}

func codexImageTimeoutTestConfig(responseHeader, streamIdle, total string) *config.Config {
	return &config.Config{Codex: config.CodexConfig{HTTPTimeouts: config.CodexHTTPTimeoutConfig{
		Connect: "1s", ResponseHeader: responseHeader, StreamIdle: streamIdle, Total: total,
	}}}
}

func codexImageTimeoutTestRequest(model string) cliproxyexecutor.Request {
	return cliproxyexecutor.Request{Model: model, Payload: []byte(`{"model":"` + model + `","prompt":"private prompt"}`)}
}

func codexImageTimeoutResponse(body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}
}

func codexImageStreamError(result *cliproxyexecutor.StreamResult) error {
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			return chunk.Err
		}
	}
	return nil
}

func assertCodexImageTimeout(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) || got == nil || got.Error() != want.Error() {
		t.Fatalf("error = %v, want fixed %v", got, want)
	}
	var requestScoped interface{ IsRequestScoped() bool }
	if !errors.As(got, &requestScoped) || !requestScoped.IsRequestScoped() {
		t.Fatalf("post-connect timeout %T is not request-scoped", got)
	}
	for _, secret := range []string{"private prompt", "images.private.test", "/images/"} {
		if strings.Contains(got.Error(), secret) {
			t.Fatalf("timeout error leaked %q: %q", secret, got)
		}
	}
}

type codexImageWaitBody struct{ ctx context.Context }

func (b *codexImageWaitBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*codexImageWaitBody) Close() error { return nil }

type codexImagePacedBody struct{ ctx context.Context }

func (b *codexImagePacedBody) Read(p []byte) (int, error) {
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-time.After(10 * time.Millisecond):
		p[0] = 'x'
		return 1, nil
	}
}

func (*codexImagePacedBody) Close() error { return nil }

func TestCodexExecutorDirectOpenAIImageGenerationUsesImagesEndpoint(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotAccept string
	var gotUA string
	var gotVersion string
	var gotTurnMetadata string
	var gotClientRequestID string
	var gotOriginator string
	var gotBody []byte
	upstreamBody := []byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}],"usage":{"total_tokens":100,"input_tokens":50,"output_tokens":50}}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotUA = r.Header.Get("User-Agent")
		gotVersion = r.Header.Get("Version")
		gotTurnMetadata = r.Header.Get("X-Codex-Turn-Metadata")
		gotClientRequestID = r.Header.Get("X-Client-Request-Id")
		gotOriginator = r.Header.Get("Originator")
		var errRead error
		gotBody, errRead = io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read body: %v", errRead)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamBody)
	}))
	defer server.Close()

	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":            "downstream-client/9.9",
		"Version":               "0.135.0",
		"X-Codex-Turn-Metadata": `{"turn_id":"turn-1"}`,
		"X-Client-Request-Id":   "client-request-1",
		"Originator":            "Codex Desktop",
	})
	executor := NewCodexExecutor(&config.Config{})
	resp, errExecute := executor.Execute(ctx, newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "codex/gpt-image-1.5",
		Payload: []byte(`{"model":"codex/gpt-image-1.5","prompt":"A cute baby sea otter","n":1,"size":"1024x1024","quality":"high","background":"opaque","output_format":"jpeg","output_compression":70,"moderation":"low","extra":{"preserve":true},"stream":false}`),
	}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if gotPath != "/images/generations" {
		t.Fatalf("path = %q, want /images/generations", gotPath)
	}
	if gotAuth != "Bearer codex-token" {
		t.Fatalf("Authorization = %q, want Bearer codex-token", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", gotAccept)
	}
	if gotUA != codexUserAgent {
		t.Fatalf("User-Agent = %q, want codex default %q", gotUA, codexUserAgent)
	}
	if gotVersion != "0.135.0" {
		t.Fatalf("Version = %q, want %q", gotVersion, "0.135.0")
	}
	if gotTurnMetadata != `{"turn_id":"turn-1"}` {
		t.Fatalf("X-Codex-Turn-Metadata = %q, want %q", gotTurnMetadata, `{"turn_id":"turn-1"}`)
	}
	if gotClientRequestID != "client-request-1" {
		t.Fatalf("X-Client-Request-Id = %q, want %q", gotClientRequestID, "client-request-1")
	}
	if gotOriginator != codexOriginator {
		t.Fatalf("Originator = %q, want %q", gotOriginator, codexOriginator)
	}
	if got := gjson.GetBytes(gotBody, "model").String(); got != "gpt-image-1.5" {
		t.Fatalf("model = %q, want gpt-image-1.5; body=%s", got, string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "extra.preserve").Bool(); !got {
		t.Fatalf("extra.preserve missing from body: %s", string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "output_compression").Int(); got != 70 {
		t.Fatalf("output_compression = %d, want 70; body=%s", got, string(gotBody))
	}
	if gjson.GetBytes(gotBody, "stream").Exists() {
		t.Fatalf("stream should be removed for non-stream execution: %s", string(gotBody))
	}
	if !bytes.Equal(resp.Payload, upstreamBody) {
		t.Fatalf("payload = %s, want %s", string(resp.Payload), string(upstreamBody))
	}
}

func TestCodexExecutorDirectOpenAIImageGenerationStreamsImagesEndpoint(t *testing.T) {
	var gotPath string
	var gotAccept string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")
		var errRead error
		gotBody, errRead = io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read body: %v", errRead)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: image_generation.partial_image\ndata: {\"type\":\"image_generation.partial_image\",\"b64_json\":\"AA==\",\"partial_image_index\":0}\n\n"))
		_, _ = w.Write([]byte("event: image_generation.completed\ndata: {\"type\":\"image_generation.completed\",\"b64_json\":\"BB==\",\"usage\":{\"total_tokens\":10,\"input_tokens\":4,\"output_tokens\":6}}\n\n"))
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	stream, errStream := executor.ExecuteStream(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-image-2",
		Payload: []byte(`{"model":"gpt-image-2","prompt":"A cute baby sea otter","partial_images":2}`),
	}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
	if errStream != nil {
		t.Fatalf("ExecuteStream() error = %v", errStream)
	}

	var combined bytes.Buffer
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
	}

	if gotPath != "/images/generations" {
		t.Fatalf("path = %q, want /images/generations", gotPath)
	}
	if gotAccept != "text/event-stream" {
		t.Fatalf("Accept = %q, want text/event-stream", gotAccept)
	}
	if !gjson.GetBytes(gotBody, "stream").Bool() {
		t.Fatalf("stream flag missing from upstream body: %s", string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "partial_images").Int(); got != 2 {
		t.Fatalf("partial_images = %d, want 2; body=%s", got, string(gotBody))
	}
	out := combined.String()
	if !strings.Contains(out, "event: image_generation.partial_image") || !strings.Contains(out, "event: image_generation.completed") {
		t.Fatalf("stream output missing image events: %q", out)
	}
}

func TestCodexExecutorDirectOpenAIImageEditUsesImagesEditEndpointForJSON(t *testing.T) {
	var gotPath string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var errRead error
		gotBody, errRead = io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read body: %v", errRead)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}],"usage":{"total_tokens":10}}`))
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	_, errExecute := executor.Execute(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-image-2",
		Payload: []byte(`{"model":"gpt-image-2","prompt":"Replace the background","images":[{"file_id":"file-abc123"}],"mask":{"file_id":"file-mask123"},"size":"1024x1024","quality":"high","output_format":"png","output_compression":100,"stream":false}`),
	}, codexOpenAIImageTestOptions(codexImagesEditsPath, false))
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if gotPath != "/images/edits" {
		t.Fatalf("path = %q, want /images/edits", gotPath)
	}
	if got := gjson.GetBytes(gotBody, "model").String(); got != "gpt-image-2" {
		t.Fatalf("model = %q, want gpt-image-2; body=%s", got, string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "images.0.file_id").String(); got != "file-abc123" {
		t.Fatalf("images.0.file_id = %q, want file-abc123; body=%s", got, string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "mask.file_id").String(); got != "file-mask123" {
		t.Fatalf("mask.file_id = %q, want file-mask123; body=%s", got, string(gotBody))
	}
	if gjson.GetBytes(gotBody, "stream").Exists() {
		t.Fatalf("stream should be removed for non-stream execution: %s", string(gotBody))
	}
}

func TestCodexExecutorDirectOpenAIImageEditUsesImagesEditEndpointForMultipart(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if errWrite := writer.WriteField("model", "codex/gpt-image-1.5"); errWrite != nil {
		t.Fatalf("write model field: %v", errWrite)
	}
	if errWrite := writer.WriteField("prompt", "Create a lovely gift basket"); errWrite != nil {
		t.Fatalf("write prompt field: %v", errWrite)
	}
	if errWrite := writer.WriteField("output_format", "webp"); errWrite != nil {
		t.Fatalf("write output_format field: %v", errWrite)
	}
	if errWrite := writer.WriteField("n", "2"); errWrite != nil {
		t.Fatalf("write n field: %v", errWrite)
	}
	if errWrite := writer.WriteField("stream", "false"); errWrite != nil {
		t.Fatalf("write stream field: %v", errWrite)
	}
	imagePart, errCreate := writer.CreateFormFile("image[]", "source.png")
	if errCreate != nil {
		t.Fatalf("create image field: %v", errCreate)
	}
	if _, errWrite := imagePart.Write([]byte("png-data")); errWrite != nil {
		t.Fatalf("write image data: %v", errWrite)
	}
	maskPart, errCreateMask := writer.CreateFormFile("mask", "mask.png")
	if errCreateMask != nil {
		t.Fatalf("create mask field: %v", errCreateMask)
	}
	if _, errWrite := maskPart.Write([]byte("mask-data")); errWrite != nil {
		t.Fatalf("write mask data: %v", errWrite)
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatalf("close multipart writer: %v", errClose)
	}

	var gotPath string
	var gotContentType string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		var errRead error
		gotBody, errRead = io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read body: %v", errRead)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}]}`))
	}))
	defer server.Close()

	opts := codexOpenAIImageTestOptions(codexImagesEditsPath, false)
	opts.Headers = http.Header{"Content-Type": []string{writer.FormDataContentType()}}
	executor := NewCodexExecutor(&config.Config{})
	_, errExecute := executor.Execute(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "codex/gpt-image-1.5",
		Payload: body.Bytes(),
	}, opts)
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if gotPath != "/images/edits" {
		t.Fatalf("path = %q, want /images/edits", gotPath)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	if !json.Valid(gotBody) {
		t.Fatalf("body is not valid JSON: %s", string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "model").String(); got != "gpt-image-1.5" {
		t.Fatalf("model = %q, want gpt-image-1.5; body=%s", got, string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "prompt").String(); got != "Create a lovely gift basket" {
		t.Fatalf("prompt = %q", got)
	}
	if got := gjson.GetBytes(gotBody, "output_format").String(); got != "webp" {
		t.Fatalf("output_format = %q, want webp; body=%s", got, string(gotBody))
	}
	if got := gjson.GetBytes(gotBody, "n").Int(); got != 2 {
		t.Fatalf("n = %d, want 2; body=%s", got, string(gotBody))
	}
	if gjson.GetBytes(gotBody, "stream").Exists() {
		t.Fatalf("stream should be removed for non-stream execution: %s", string(gotBody))
	}
	imageURL := gjson.GetBytes(gotBody, "images.0.image_url").String()
	if !strings.Contains(imageURL, ";base64,cG5nLWRhdGE=") {
		t.Fatalf("images.0.image_url = %q, want png-data data URL; body=%s", imageURL, string(gotBody))
	}
	maskURL := gjson.GetBytes(gotBody, "mask.image_url").String()
	if !strings.Contains(maskURL, ";base64,bWFzay1kYXRh") {
		t.Fatalf("mask.image_url = %q, want mask-data data URL; body=%s", maskURL, string(gotBody))
	}
}

func TestCodexExecutorDirectOpenAIImage25Models(t *testing.T) {
	testModels := []string{
		"gpt-image-2.5",
		"gpt-image-2.5-flare",
		"gpt-image-2.5-sunburst",
		"codex/gpt-image-2.5",
		"codex/gpt-image-2.5-flare",
		"codex/gpt-image-2.5-sunburst",
		"GPT-Image-2.5(medium)",
		"codex/GPT-Image-2.5-Flare(high)",
	}

	for _, model := range testModels {
		t.Run("generate/"+model, func(t *testing.T) {
			baseModel := codexOpenAIImageBaseModel(model)
			if !codexIsDirectOpenAIImageModel(baseModel) {
				t.Fatalf("expected codexIsDirectOpenAIImageModel(%q) = true", baseModel)
			}

			var gotPath string
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				var errRead error
				gotBody, errRead = io.ReadAll(r.Body)
				if errRead != nil {
					t.Fatalf("read body: %v", errRead)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}],"usage":{"total_tokens":10}}`))
			}))
			defer server.Close()

			executor := NewCodexExecutor(&config.Config{})
			_, errExecute := executor.Execute(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   model,
				Payload: []byte(`{"model":"` + model + `","prompt":"draw something"}`),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}

			if gotPath != "/images/generations" {
				t.Fatalf("path = %q, want /images/generations", gotPath)
			}
			if got := gjson.GetBytes(gotBody, "model").String(); got != baseModel {
				t.Fatalf("model = %q, want %s; body=%s", got, baseModel, string(gotBody))
			}
		})

		t.Run("edit/"+model, func(t *testing.T) {
			baseModel := codexOpenAIImageBaseModel(model)
			var gotPath string
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				var errRead error
				gotBody, errRead = io.ReadAll(r.Body)
				if errRead != nil {
					t.Fatalf("read body: %v", errRead)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA=="}],"usage":{"total_tokens":10}}`))
			}))
			defer server.Close()

			executor := NewCodexExecutor(&config.Config{})
			_, errExecute := executor.Execute(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   model,
				Payload: []byte(`{"model":"` + model + `","prompt":"edit something","images":[{"file_id":"f1"}]}`),
			}, codexOpenAIImageTestOptions(codexImagesEditsPath, false))
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}

			if gotPath != "/images/edits" {
				t.Fatalf("path = %q, want /images/edits", gotPath)
			}
			if got := gjson.GetBytes(gotBody, "model").String(); got != baseModel {
				t.Fatalf("model = %q, want %s; body=%s", got, baseModel, string(gotBody))
			}
		})

		t.Run("stream/"+model, func(t *testing.T) {
			baseModel := codexOpenAIImageBaseModel(model)
			var gotPath string
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				var errRead error
				gotBody, errRead = io.ReadAll(r.Body)
				if errRead != nil {
					t.Fatalf("read body: %v", errRead)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("event: image_generation.completed\ndata: {\"type\":\"image_generation.completed\",\"b64_json\":\"BB==\"}\n\n"))
			}))
			defer server.Close()

			executor := NewCodexExecutor(&config.Config{})
			stream, errStream := executor.ExecuteStream(context.Background(), newCodexOpenAIImageTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   model,
				Payload: []byte(`{"model":"` + model + `","prompt":"stream something"}`),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
			if errStream != nil {
				t.Fatalf("ExecuteStream() error = %v", errStream)
			}
			for chunk := range stream.Chunks {
				if chunk.Err != nil {
					t.Fatalf("stream chunk error = %v", chunk.Err)
				}
			}

			if gotPath != "/images/generations" {
				t.Fatalf("path = %q, want /images/generations", gotPath)
			}
			if got := gjson.GetBytes(gotBody, "model").String(); got != baseModel {
				t.Fatalf("model = %q, want %s; body=%s", got, baseModel, string(gotBody))
			}
		})
	}
}
