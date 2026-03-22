package handler

import (
	"fmt"
	"net/http"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
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

func BatchAction(c *gin.Context) {
	var body struct {
		Action string `json:"action"`
		IDs    []uint `json:"ids"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "参数错误"})
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "请先选择实例"})
		return
	}

	var instances []models.EcsInstance
	database.DB.Where("id IN ?", body.IDs).Find(&instances)

	count := 0
	for _, inst := range instances {
		switch body.Action {
		case "check":
			go service.CheckAndManageInstance(inst.ID)
			count++
		case "start":
			if inst.Status == "Stopped" {
				service.ECSAction(inst.ID, "start")
				count++
			}
		case "stop":
			if inst.Status == "Running" {
				service.ECSAction(inst.ID, "stop")
				count++
			}
		}
	}

	actionNames := map[string]string{"start": "启动", "stop": "停止", "check": "检查"}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("已对 %d 个实例执行 %s 操作", count, actionNames[body.Action]),
	})
}

func CheckAll(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Where("monitor_enabled = ?", true).Find(&instances)
	for _, inst := range instances {
		go service.CheckAndManageInstance(inst.ID)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("已触发检查 %d 个实例", len(instances))})
}

func DashboardProbeOverview(c *gin.Context) {
	var servers []models.ProbeServer
	database.DB.Order("created_at desc").Find(&servers)

	online, offline := 0, 0
	type miniServer struct {
		ID       uint   `json:"id"`
		Name     string `json:"name"`
		IsOnline bool   `json:"is_online"`
	}
	var miniList []miniServer
	for _, s := range servers {
		isOnline := s.IsOnline
		if isOnline {
			online++
		} else {
			offline++
		}
		if len(miniList) < 8 {
			miniList = append(miniList, miniServer{ID: s.ID, Name: s.Name, IsOnline: isOnline})
		}
	}

	var totalRules, enabledRules int64
	database.DB.Model(&models.DnsFailover{}).Count(&totalRules)
	database.DB.Model(&models.DnsFailover{}).Where("enabled = ?", true).Count(&enabledRules)

	c.JSON(http.StatusOK, gin.H{
		"probe": gin.H{"total": len(servers), "online": online, "offline": offline, "servers": miniList},
		"dns":   gin.H{"total_rules": totalRules, "enabled_rules": enabledRules},
	})
}
