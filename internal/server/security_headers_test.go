package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Cong0707/sso/internal/config"
	"github.com/gin-gonic/gin"
)

func TestContentSecurityPolicyAllowsCAPWorkers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{Cfg: config.Config{CookieSecure: true}}
	router := gin.New()
	router.Use(server.requestContext)
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	policy := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "worker-src 'self' blob:") {
		t.Fatalf("CAP worker source missing from CSP: %q", policy)
	}
	if response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("secure deployment must emit HSTS")
	}
}
