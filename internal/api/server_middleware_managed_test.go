package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestManagedInferenceKeysFenceRealtimeClientSecretBypass(t *testing.T) {
	key, err := sdkaccess.GenerateEnvironmentKey()
	if err != nil {
		t.Fatal(err)
	}
	manager := sdkaccess.NewManager()
	manager.SetEnvironmentKeyVerifier(func(given string) (string, bool) {
		return "private-managed-principal", given == key
	})
	router := gin.New()
	invocations := 0
	router.POST("/v1/realtime/client_secrets", realtimeStandardAuthMiddleware(manager), func(c *gin.Context) {
		invocations++
		c.Status(http.StatusOK)
	})
	router.GET("/v1/realtime", realtimeAuthMiddleware(manager, nil), func(c *gin.Context) {
		invocations++
		c.Status(http.StatusOK)
	})
	request := func(method, path, bearer string) int {
		r := httptest.NewRequest(method, path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, r)
		return response.Code
	}
	if status := request(http.MethodPost, "/v1/realtime/client_secrets", key); status != http.StatusForbidden {
		t.Fatalf("managed key minted unrevocable delegated secret: %d", status)
	}
	if status := request(http.MethodGet, "/v1/realtime", "old-ephemeral-client-secret"); status != http.StatusUnauthorized {
		t.Fatalf("prior ephemeral secret bypassed new key authority: %d", status)
	}
	if status := request(http.MethodGet, "/v1/realtime", key); status != http.StatusOK || invocations != 1 {
		t.Fatalf("managed bearer rejected through realtime admission: %d (%d invocations)", status, invocations)
	}
}
