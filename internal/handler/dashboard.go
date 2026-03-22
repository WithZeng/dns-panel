package handler

import (
	"net/http"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func Dashboard(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Order("tag, name").Find(&instances)

	tags := map[string]bool{}
	var totalTraffic float64
	var online, stopped int
	for _, inst := range instances {
		if inst.Tag != "" {
			tags[inst.Tag] = true
		}
		totalTraffic += inst.CurrentMonthTraffic
		switch inst.Status {
		case "Running", "Starting":
			online++
		case "Stopped":
			stopped++
		}
	}

	tagList := make([]string, 0, len(tags))
	for t := range tags {
		tagList = append(tagList, t)
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"instances":    instances,
		"total":        len(instances),
		"online":       online,
		"stopped":      stopped,
		"totalTraffic": totalTraffic,
		"tags":         tagList,
		"username":     c.GetString("username"),
	})
}

func APIInstances(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Order("tag, name").Find(&instances)

	type instanceResp struct {
		models.EcsInstance
		TrafficPct float64 `json:"traffic_pct"`
	}

	result := make([]instanceResp, len(instances))
	for i, inst := range instances {
		result[i].EcsInstance = inst
		var limit float64
		if inst.TrafficStrategy == "life" {
			limit = inst.LifeTotalLimit
		} else {
			limit = inst.MonthlyLimit
		}
		if limit > 0 {
			var used float64
			if inst.TrafficStrategy == "life" {
				used = inst.TotalTrafficSum
			} else {
				used = inst.CurrentMonthTraffic
			}
			result[i].TrafficPct = used / limit * 100
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "instances": result})
}
