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

func SendAlert(notifyType, webhookURL, message, instanceName string) bool {
	sender, ok := senders[notifyType]
	if !ok {
		log.Printf("Unknown notify type: %s", notifyType)
		logNotification(instanceName, notifyType, message, false, fmt.Sprintf("Unknown type: %s", notifyType), 1)
		return false
	}

	var lastErr string
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := sender(webhookURL, message); err == nil {
			log.Printf("Alert sent via %s (attempt %d)", notifyType, attempt)
			logNotification(instanceName, notifyType, message, true, "", attempt)
			return true
		} else {
			lastErr = err.Error()
			log.Printf("Alert attempt %d/%d failed (%s): %s", attempt, maxRetries, notifyType, lastErr)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
		}
	}

	log.Printf("Alert failed after %d attempts (%s): %s", maxRetries, notifyType, lastErr)
	logNotification(instanceName, notifyType, message, false, lastErr, maxRetries)
	return false
}

var senders = map[string]func(string, string) error{
	"wechat":   sendWechat,
	"dingtalk":  sendDingtalk,
	"telegram":  sendTelegram,
}

func sendWechat(webhookURL, message string) error {
	payload := map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": message},
	}
	return postJSON(webhookURL, payload)
}

func sendDingtalk(webhookURL, message string) error {
	payload := map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": message},
	}
	return postJSON(webhookURL, payload)
}

func sendTelegram(webhookURL, message string) error {
	payload := map[string]any{"text": message}
	return postJSON(webhookURL, payload)
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
