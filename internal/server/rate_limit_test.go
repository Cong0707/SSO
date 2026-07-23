package server

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/google/uuid"
)

func TestRedisRateLimitIsSharedAcrossServers(t *testing.T) {
	address := os.Getenv("SSO_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("set SSO_TEST_REDIS_ADDR to run the Redis integration test")
	}
	cfg := config.Config{
		MasterKey:          []byte("0123456789abcdef0123456789abcdef"),
		RateLimitEnabled:   true,
		RedisAddr:          address,
		RedisPassword:      os.Getenv("SSO_TEST_REDIS_PASSWORD"),
		RedisKeyPrefix:     "xem-sso-test-" + uuid.NewString(),
		RateLimitIdentify:  17,
		RateLimitSensitive: 17,
	}
	firstClient, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("connect first redis client: %v", err)
	}
	defer firstClient.Close()
	secondClient, err := newRedisClient(cfg)
	if err != nil {
		t.Fatalf("connect second redis client: %v", err)
	}
	defer secondClient.Close()
	servers := []*Server{{Cfg: cfg, Redis: firstClient}, {Cfg: cfg, Redis: secondClient}}

	const requests = 64
	var allowed atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			ok, _, limitErr := servers[index%len(servers)].consumeRateLimit("identify", "User@Example.com", cfg.RateLimitIdentify, time.Minute)
			if limitErr != nil {
				t.Errorf("consume rate limit: %v", limitErr)
				return
			}
			if ok {
				allowed.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if got := allowed.Load(); got != int64(cfg.RateLimitIdentify) {
		t.Fatalf("allowed requests = %d, want %d", got, cfg.RateLimitIdentify)
	}

	keys, err := firstClient.Keys(t.Context(), cfg.RedisKeyPrefix+":rate:*").Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("rate limit keys = %v, err = %v", keys, err)
	}
	if strings.Contains(strings.ToLower(keys[0]), "user@example.com") {
		t.Fatalf("rate limit key exposes the subject: %s", keys[0])
	}
	if ttl := firstClient.PTTL(t.Context(), keys[0]).Val(); ttl <= 0 || ttl > 2*time.Minute {
		t.Fatalf("unexpected rate limit ttl: %s", ttl)
	}
	_ = firstClient.Del(t.Context(), keys...).Err()
}

func TestDisabledRateLimitDoesNotRequireRedis(t *testing.T) {
	server := &Server{Cfg: config.Config{RateLimitEnabled: false}}
	allowed, retryAfter, err := server.consumeRateLimit("test", fmt.Sprint(time.Now().UnixNano()), 1, time.Minute)
	if err != nil || !allowed || retryAfter != 0 {
		t.Fatalf("disabled limiter returned allowed=%v retry=%s err=%v", allowed, retryAfter, err)
	}
}
