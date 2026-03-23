package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
)

const (
	maxRetries = 3
	retryDelay = 2 * time.Second
)

func SendAlert(message, instanceName string) bool {
	var cfg models.AlertConfig
	if err := database.DB.First(&cfg).Error; err != nil || !cfg.Enabled {
		return false
	}

	if cfg.TGBotToken == "" || cfg.TGChatID == "" {
		logNotification(instanceName, "telegram", message, false, "Bot Token 或 Chat ID 未配置", 1)
		return false
	}

	var lastErr string
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := sendTelegram(cfg.TGBotToken, cfg.TGChatID, message); err == nil {
			log.Printf("Alert sent via Telegram (attempt %d)", attempt)
			logNotification(instanceName, "telegram", message, true, "", attempt)
			return true
		} else {
			lastErr = err.Error()
			log.Printf("Alert attempt %d/%d failed (telegram): %s", attempt, maxRetries, lastErr)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
		}
	}

	log.Printf("Alert failed after %d attempts (telegram): %s", maxRetries, lastErr)
	logNotification(instanceName, "telegram", message, false, lastErr, maxRetries)
	return false
}

func sendTelegram(botToken, chatID, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "HTML",
	}
	return postJSON(url, payload)
}

func postJSON(url string, payload any) error {
	data, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func logNotification(instanceName, notifyType, message string, success bool, errMsg string, attempts int) {
	if len(message) > 2000 {
		message = message[:2000]
	}
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	entry := models.NotificationLog{
		InstanceName: instanceName,
		NotifyType:   notifyType,
		Message:      message,
		Success:      success,
		ErrorMessage: errMsg,
		Attempts:     attempts,
	}
	if err := database.DB.Create(&entry).Error; err != nil {
		log.Printf("Failed to log notification: %v", err)
	}
}
