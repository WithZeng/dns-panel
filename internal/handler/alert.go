package handler

import (
	"net/http"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/gin-gonic/gin"
)

func AlertConfigPage(c *gin.Context) {
	var cfg models.AlertConfig
	database.DB.FirstOrCreate(&cfg)
	c.HTML(http.StatusOK, "alert_config.html", gin.H{
		"config":   cfg,
		"username": c.GetString("username"),
	})
}

func AlertConfigPost(c *gin.Context) {
	var cfg models.AlertConfig
	database.DB.FirstOrCreate(&cfg)

	cfg.NotifyType = c.PostForm("notify_type")
	cfg.WebhookURL = c.PostForm("webhook_url")
	cfg.Enabled = c.PostForm("enabled") == "on"
	database.DB.Save(&cfg)

	c.Redirect(http.StatusFound, "/alert_config")
}

func TestNotification(c *gin.Context) {
	var cfg models.AlertConfig
	if err := database.DB.First(&cfg).Error; err != nil || cfg.WebhookURL == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "请先配置 Webhook 地址"})
		return
	}

	ok := service.SendAlert(cfg.NotifyType, cfg.WebhookURL, "DNS Panel 测试通知 - 如果你看到这条消息，说明通知配置正确。", "test")
	if ok {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "测试通知发送成功"})
	} else {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "发送失败，请检查 Webhook 地址"})
	}
}
