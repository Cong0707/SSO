package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Cong0707/sso/internal/config"
	"github.com/gin-gonic/gin"
)

func TestRouterAccessLogOmitsSensitiveQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousWriter := gin.DefaultWriter
	var output bytes.Buffer
	gin.DefaultWriter = &output
	t.Cleanup(func() { gin.DefaultWriter = previousWriter })

	application := &Server{Cfg: config.Config{WebDir: t.TempDir()}}
	request := httptest.NewRequest(http.MethodGet, "/livez?code=oauth-secret&state=state-secret", nil)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	logLine := output.String()
	if strings.Contains(logLine, "oauth-secret") || strings.Contains(logLine, "state-secret") || strings.Contains(logLine, "?code=") {
		t.Fatalf("access log exposed sensitive query data: %s", logLine)
	}
}
