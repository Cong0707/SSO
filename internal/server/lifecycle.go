package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const lifecycleLockTTL = 2 * time.Minute

func (s *Server) recordLifecycleEvent(tx *gorm.DB, userID uint64, eventType string, extra map[string]any) error {
	result := tx.Model(&model.User{}).Where("id = ?", userID).
		UpdateColumn("identity_version", gorm.Expr("identity_version + 1"))
	if result.Error != nil || result.RowsAffected != 1 {
		return fmt.Errorf("increment identity version: %w", result.Error)
	}
	var user model.User
	if err := tx.Select("id", "status", "role", "locale", "locale_source", "identity_version", "merged_into_user_id").First(&user, userID).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	eventID := uuid.NewString()
	payload := map[string]any{
		"event_id":         eventID,
		"type":             eventType,
		"occurred_at":      now,
		"sub":              strconv.FormatUint(user.ID, 10),
		"identity_version": user.IdentityVersion,
		"status":           user.Status,
		"role":             user.Role,
		"locale":           projectedLocale(&user),
	}
	if eventType == "profile.updated" {
		payload["locale_source"] = user.LocaleSource
	}
	if user.MergedIntoUserID != nil {
		payload["canonical_sub"] = strconv.FormatUint(*user.MergedIntoUserID, 10)
	}
	for key, value := range extra {
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return tx.Create(&model.LifecycleEvent{
		ID: eventID, CreatedAt: now, UserID: userID, IdentityVersion: user.IdentityVersion,
		Type: eventType, Payload: string(encoded), NextAttemptAt: now,
	}).Error
}

func (s *Server) startLifecycleDispatcher() {
	if s.Cfg.LifecycleWebhookURL == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.outboxCancel = cancel
	s.outboxDone = make(chan struct{})
	go func() {
		defer close(s.outboxDone)
		ticker := time.NewTicker(s.Cfg.OutboxPollInterval)
		defer ticker.Stop()
		for {
			for s.deliverNextLifecycleEvent(ctx) {
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *Server) deliverNextLifecycleEvent(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	now := time.Now().UTC()
	var event model.LifecycleEvent
	claimed := false
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("delivered_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= ? AND (locked_at IS NULL OR locked_at < ?)", now, now.Add(-lifecycleLockTTL)).
			Order("created_at ASC").First(&event).Error; err != nil {
			return err
		}
		result := tx.Model(&model.LifecycleEvent{}).
			Where("id = ? AND delivered_at IS NULL AND dead_lettered_at IS NULL AND (locked_at IS NULL OR locked_at < ?)", event.ID, now.Add(-lifecycleLockTTL)).
			Updates(map[string]any{"locked_at": &now, "attempts": gorm.Expr("attempts + 1")})
		if result.Error != nil {
			return result.Error
		}
		claimed = result.RowsAffected == 1
		if claimed {
			event.Attempts++
		}
		return nil
	})
	if err != nil || !claimed {
		return false
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Cfg.LifecycleWebhookURL, bytes.NewBufferString(event.Payload))
	if err == nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Xem-Event-ID", event.ID)
		request.Header.Set("X-Xem-Event-Type", event.Type)
		request.Header.Set("X-Xem-Signature-SHA256", security.HMACToken([]byte(s.Cfg.LifecycleWebhookSecret), event.Payload))
		client := &http.Client{Timeout: 10 * time.Second}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			err = requestErr
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
			}
		}
	}
	completedAt := time.Now().UTC()
	if err == nil {
		_ = s.DB.Model(&model.LifecycleEvent{}).Where("id = ? AND delivered_at IS NULL", event.ID).
			Updates(map[string]any{"delivered_at": &completedAt, "locked_at": nil, "last_error": ""}).Error
		return true
	}
	updates := map[string]any{"locked_at": nil, "last_error": err.Error()}
	if event.Attempts >= s.Cfg.OutboxMaxAttempts {
		updates["dead_lettered_at"] = &completedAt
	} else {
		delay := time.Duration(1<<min(event.Attempts, 9)) * 5 * time.Second
		if delay > time.Hour {
			delay = time.Hour
		}
		updates["next_attempt_at"] = completedAt.Add(delay)
	}
	_ = s.DB.Model(&model.LifecycleEvent{}).Where("id = ? AND delivered_at IS NULL", event.ID).Updates(updates).Error
	return true
}

func (s *Server) adminListLifecycleEvents(c *gin.Context) {
	var events []model.LifecycleEvent
	query := s.DB.Order("created_at DESC").Limit(200)
	if c.Query("state") == "dead_letter" {
		query = query.Where("dead_lettered_at IS NOT NULL")
	} else if c.Query("state") == "pending" {
		query = query.Where("delivered_at IS NULL AND dead_lettered_at IS NULL")
	}
	if err := query.Find(&events).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取生命周期事件失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": events})
}

func (s *Server) adminRetryLifecycleEvent(c *gin.Context) {
	now := time.Now().UTC()
	result := s.DB.Model(&model.LifecycleEvent{}).Where("id = ?", c.Param("id")).Updates(map[string]any{
		"dead_lettered_at": nil, "locked_at": nil, "next_attempt_at": now, "last_error": "",
	})
	if result.Error != nil {
		s.serveError(c, http.StatusInternalServerError, "重试事件失败")
		return
	}
	if result.RowsAffected != 1 {
		s.serveError(c, http.StatusNotFound, "事件不存在")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}
