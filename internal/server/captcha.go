package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var captchaHTTPClient = &http.Client{Timeout: 10 * time.Second}

func (s *Server) authConfig(c *gin.Context) {
	mode := strings.ToLower(s.setting(settingCaptchaMode, "none"))
	data := gin.H{
		"registration_enabled": s.settingBool(settingRegistrationEnabled, s.Cfg.RegistrationEnabled),
		"captcha":              gin.H{"mode": mode},
	}
	captcha := data["captcha"].(gin.H)
	if mode == "turnstile" {
		captcha["site_key"] = s.setting(settingTurnstileSiteKey, "")
	}
	if mode == "cap" {
		siteKey := strings.Trim(s.setting(settingCAPSiteKey, ""), "/")
		if siteKey != "" {
			captcha["api_endpoint"] = "/api/cap/" + siteKey + "/"
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func (s *Server) verifyCaptcha(token, remoteIP string) error {
	mode := strings.ToLower(s.setting(settingCaptchaMode, "none"))
	if mode == "none" {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("请先完成人机验证")
	}
	switch mode {
	case "turnstile":
		response, err := captchaHTTPClient.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", url.Values{
			"secret": {s.setting(settingTurnstileSecretKey, "")}, "response": {token}, "remoteip": {remoteIP},
		})
		if err != nil {
			return fmt.Errorf("Turnstile 校验请求失败: %w", err)
		}
		defer response.Body.Close()
		var result struct {
			Success bool `json:"success"`
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || !result.Success {
			return fmt.Errorf("Turnstile 校验失败，请刷新后重试")
		}
		return nil
	case "cap":
		endpoint := strings.TrimRight(s.setting(settingCAPServerURL, ""), "/") + "/" + strings.Trim(s.setting(settingCAPSiteKey, ""), "/") + "/siteverify"
		payload, _ := json.Marshal(gin.H{"secret": s.setting(settingCAPSecretKey, ""), "response": token, "remoteip": remoteIP})
		request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("Cap 校验配置无效")
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := captchaHTTPClient.Do(request)
		if err != nil {
			return fmt.Errorf("Cap 校验请求失败: %w", err)
		}
		defer response.Body.Close()
		var result struct {
			Success bool `json:"success"`
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil || !result.Success {
			return fmt.Errorf("Cap 校验失败，请刷新后重试")
		}
		return nil
	default:
		return fmt.Errorf("人机验证配置无效")
	}
}

func (s *Server) capProxy(c *gin.Context) {
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodPost {
		s.serveError(c, http.StatusMethodNotAllowed, "Cap 代理仅允许 GET 和 POST")
		return
	}
	proxyPath := strings.TrimPrefix(c.Param("proxyPath"), "/")
	siteKey := strings.Trim(s.setting(settingCAPSiteKey, ""), "/")
	if siteKey == "" || (proxyPath != siteKey && !strings.HasPrefix(proxyPath, siteKey+"/")) {
		s.serveError(c, http.StatusNotFound, "Cap 路径不存在")
		return
	}
	target, err := url.Parse(s.setting(settingCAPServerURL, ""))
	if err != nil || target.Scheme == "" || target.Host == "" {
		s.serveError(c, http.StatusBadGateway, "PoW 服务地址无效")
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(request *http.Request) {
		original(request)
		request.URL.Path = strings.TrimRight(target.Path, "/") + "/" + proxyPath
		request.URL.RawPath = ""
		request.URL.RawQuery = c.Request.URL.RawQuery
		request.Host = target.Host
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, "Cap service unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(c.Writer, c.Request)
}
