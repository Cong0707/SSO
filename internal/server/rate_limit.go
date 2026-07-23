package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func newRedisClient(cfg config.Config) (*redis.Client, error) {
	if !cfg.RateLimitEnabled {
		return nil, nil
	}
	options := &redis.Options{
		Addr:         cfg.RedisAddr,
		Password:     cfg.RedisPassword,
		DB:           cfg.RedisDB,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}
	if cfg.RedisTLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.RedisTLSServerName}
	}
	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect rate limit redis: %w", err)
	}
	return client, nil
}

func (s *Server) consumeRateLimit(action, subject string, limit int, window time.Duration) (bool, time.Duration, error) {
	if !s.Cfg.RateLimitEnabled {
		return true, 0, nil
	}
	if s.Redis == nil {
		return false, 0, fmt.Errorf("rate limit redis is not configured")
	}
	now := time.Now().UTC()
	windowStartedAt := now.Truncate(window)
	expiresAt := windowStartedAt.Add(window)
	material := strings.Join([]string{action, strings.ToLower(strings.TrimSpace(subject)), strconv.FormatInt(windowStartedAt.Unix(), 10)}, "\x00")
	keyHash := security.HMACToken(s.Cfg.MasterKey, material)
	key := s.Cfg.RedisKeyPrefix + ":rate:" + keyHash

	pipeline := s.Redis.TxPipeline()
	increment := pipeline.Incr(context.Background(), key)
	pipeline.PExpire(context.Background(), key, 2*window)
	if _, err := pipeline.Exec(context.Background()); err != nil {
		return false, 0, err
	}
	retryAfter := time.Until(expiresAt)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return increment.Val() <= int64(limit), retryAfter, nil
}

func (s *Server) enforceRateLimit(c *gin.Context, action, subject string, limit int, window time.Duration) bool {
	allowed, retryAfter, err := s.consumeRateLimit(action, subject, limit, window)
	if err != nil {
		s.serveError(c, http.StatusServiceUnavailable, "请求限流服务暂时不可用")
		return false
	}
	if allowed {
		return true
	}
	seconds := int(retryAfter.Seconds()) + 1
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
	s.serveError(c, http.StatusTooManyRequests, "请求过于频繁，请稍后重试")
	return false
}

func (s *Server) enforceRateLimitPair(c *gin.Context, action, subject string, limit int, window time.Duration) bool {
	if !s.enforceRateLimit(c, action+":ip", clientIP(c), limit, window) {
		return false
	}
	return s.enforceRateLimit(c, action+":subject", subject, limit, window)
}

func (s *Server) sensitiveRateLimit(c *gin.Context) {
	user := s.user(c)
	route := c.FullPath()
	if route == "" {
		route = c.Request.URL.Path
	}
	subject := fmt.Sprintf("user:%d:%s:%s", user.ID, c.Request.Method, route)
	if !s.enforceRateLimit(c, "sensitive", subject, s.Cfg.RateLimitSensitive, time.Minute) {
		c.Abort()
		return
	}
	c.Next()
}
