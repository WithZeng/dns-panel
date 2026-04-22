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
	role := c.GetString("role")

	q := database.DB.Model(&models.OperationLog{})
	if role != "admin" {
		username := c.GetString("username")
		userID, _ := c.Get("user_id")
		var assignedIDs []uint
		database.DB.Model(&models.UserInstance{}).Where("user_id = ?", userID).Pluck("instance_id", &assignedIDs)
		q = q.Where("operator = ? AND (instance_id IN ? OR instance_id IS NULL)", username, assignedIDs)
	}

	var total int64
	q.Count(&total)

	var logs []models.OperationLog
	q.Order("timestamp DESC").Offset((page - 1) * perPage).Limit(perPage).Find(&logs)

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	c.HTML(http.StatusOK, "logs.html", gin.H{
		"logs":       logs,
		"page":       page,
		"totalPages": totalPages,
		"total":      total,
		"username":   c.GetString("username"),
		"role":       role,
	})
}

func NotificationLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	perPage := 50
	role := c.GetString("role")

	q := database.DB.Model(&models.NotificationLog{})
	if role != "admin" {
		userID, _ := c.Get("user_id")
		var instanceIDs []uint
		database.DB.Model(&models.UserInstance{}).Where("user_id = ?", userID).Pluck("instance_id", &instanceIDs)
		var instanceNames []string
		if len(instanceIDs) > 0 {
			database.DB.Model(&models.EcsInstance{}).Where("id IN ?", instanceIDs).Pluck("instance_name", &instanceNames)
		}
		q = q.Where("instance_name IN ?", instanceNames)
	}

	var total int64
	q.Count(&total)

	var logs []models.NotificationLog
	q.Order("timestamp DESC").Offset((page - 1) * perPage).Limit(perPage).Find(&logs)

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	var cfg models.AlertConfig
	database.DB.FirstOrCreate(&cfg)

	tab := c.DefaultQuery("tab", "logs")
	canConfigure := role == "admin"
	if !canConfigure {
		tab = "logs"
	}

	c.HTML(http.StatusOK, "notification_logs.html", gin.H{
		"logs":                    logs,
		"page":                    page,
		"totalPages":              totalPages,
		"total":                   total,
		"config":                  cfg,
		"tab":                     tab,
		"canConfigureNotifications": canConfigure,
		"username":                c.GetString("username"),
		"role":                    role,
	})
}

func HelpPage(c *gin.Context) {
	c.HTML(http.StatusOK, "help.html", gin.H{
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
	})
}
