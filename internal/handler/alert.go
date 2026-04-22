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
	c.HTML(http.StatusOK, "notification_logs.html", gin.H{
		"config":   cfg,
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
		"tab":      "settings",
	})
}

func AlertConfigPost(c *gin.Context) {
	var cfg models.AlertConfig
	database.DB.FirstOrCreate(&cfg)

	cfg.NotifyType = "telegram"
	cfg.TGBotToken = c.PostForm("tg_bot_token")
	cfg.TGChatID = c.PostForm("tg_chat_id")
	cfg.Enabled = c.PostForm("enabled") == "on"
	database.DB.Save(&cfg)

	c.Redirect(http.StatusFound, "/notification_logs?tab=settings")
}

func TestNotification(c *gin.Context) {
	ok := service.SendAlert("CloudPanel 测试通知 ✅\n如果你看到这条消息，说明 Telegram Bot 配置正确。", "test")
	if ok {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "测试通知发送成功"})
	} else {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "发送失败，请检查 Bot Token 和 Chat ID"})
	}
}
