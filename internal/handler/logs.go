package handler

import (
	"math"
	"net/http"
	"strconv"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func OperationLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	var total int64
	database.DB.Model(&models.OperationLog{}).Count(&total)

	var logs []models.OperationLog
	database.DB.Order("timestamp DESC").Offset((page - 1) * perPage).Limit(perPage).Find(&logs)

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	c.HTML(http.StatusOK, "logs.html", gin.H{
		"logs":       logs,
		"page":       page,
		"totalPages": totalPages,
		"total":      total,
		"username":   c.GetString("username"),
	})
}

func NotificationLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	perPage := 50

	var total int64
	database.DB.Model(&models.NotificationLog{}).Count(&total)

	var logs []models.NotificationLog
	database.DB.Order("timestamp DESC").Offset((page - 1) * perPage).Limit(perPage).Find(&logs)

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	var cfg models.AlertConfig
	database.DB.FirstOrCreate(&cfg)

	tab := c.DefaultQuery("tab", "logs")

	c.HTML(http.StatusOK, "notification_logs.html", gin.H{
		"logs":       logs,
		"page":       page,
		"totalPages": totalPages,
		"total":      total,
		"config":     cfg,
		"tab":        tab,
		"username":   c.GetString("username"),
	})
}
