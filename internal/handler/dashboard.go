package handler

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/gin-gonic/gin"
)

func Dashboard(c *gin.Context) {
	var instances []models.EcsInstance
	tag := c.Query("tag")
	q := database.DB.Order("tag, name")
	if tag != "" {
		q = q.Where("tag = ?", tag)
	}
	q.Find(&instances)

	tags := map[string]bool{}
	var totalTraffic, totalCost float64
	var online, stopped int

	var allInstances []models.EcsInstance
	database.DB.Find(&allInstances)
	for _, inst := range allInstances {
		if inst.Tag != "" {
			tags[inst.Tag] = true
		}
	}
	for _, inst := range instances {
		totalTraffic += inst.CurrentMonthTraffic
		totalCost += inst.HourlyPrice * 24 * 30
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

	var probeServers []models.ProbeServer
	database.DB.Find(&probeServers)
	probeOnline, probeOffline := 0, 0
	for _, s := range probeServers {
		if s.IsOnline {
			probeOnline++
		} else {
			probeOffline++
		}
	}

	var dnsTotal, dnsEnabled int64
	database.DB.Model(&models.DnsFailover{}).Count(&dnsTotal)
	database.DB.Model(&models.DnsFailover{}).Where("enabled = ?", true).Count(&dnsEnabled)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"instances":    instances,
		"total":        len(instances),
		"online":       online,
		"stopped":      stopped,
		"totalTraffic": totalTraffic,
		"totalCost":    totalCost,
		"tags":         tagList,
		"currentTag":   tag,
		"probeTotal":   len(probeServers),
		"probeOnline":  probeOnline,
		"probeOffline": probeOffline,
		"dnsTotal":     dnsTotal,
		"dnsEnabled":   dnsEnabled,
		"username":     c.GetString("username"),
	})
}

func APIInstances(c *gin.Context) {
	tag := c.Query("tag")
	var instances []models.EcsInstance
	q := database.DB.Order("tag, name")
	if tag != "" {
		q = q.Where("tag = ?", tag)
	}
	q.Find(&instances)

	type instanceJSON struct {
		ID                uint    `json:"id"`
		Name              string  `json:"name"`
		InstanceID        string  `json:"instance_id"`
		RegionID          string  `json:"region_id"`
		Status            string  `json:"status"`
		PublicIP          string  `json:"public_ip"`
		IPv6Addr          string  `json:"ipv6_addr"`
		Tag               string  `json:"tag"`
		TrafficStrategy   string  `json:"traffic_strategy"`
		CurrentMonthTraffic float64 `json:"current_month_traffic"`
		MonthlyLimit      float64 `json:"monthly_limit"`
		TotalTrafficSum   float64 `json:"total_traffic_sum"`
		LifeTotalLimit    float64 `json:"life_total_limit"`
		CredentialStatus  string  `json:"credential_status"`
		CredentialError   string  `json:"credential_error"`
		LastChecked       string  `json:"last_checked"`
		TrafficPct        float64 `json:"traffic_pct"`
	}

	var online, stopped int
	var totalTraffic, totalCost float64
	result := make([]instanceJSON, len(instances))

	for i, inst := range instances {
		if inst.Status == "Running" || inst.Status == "Starting" {
			online++
		} else if inst.Status == "Stopped" {
			stopped++
		}
		totalTraffic += inst.CurrentMonthTraffic
		totalCost += inst.HourlyPrice * 24 * 30

		r := instanceJSON{
			ID: inst.ID, Name: inst.Name, InstanceID: inst.InstanceID,
			RegionID: inst.RegionID, Status: inst.Status, PublicIP: inst.PublicIP,
			IPv6Addr: inst.IPv6Addr, Tag: inst.Tag, TrafficStrategy: inst.TrafficStrategy,
			CurrentMonthTraffic: inst.CurrentMonthTraffic, MonthlyLimit: inst.MonthlyLimit,
			TotalTrafficSum: inst.TotalTrafficSum, LifeTotalLimit: inst.LifeTotalLimit,
			CredentialStatus: inst.CredentialStatus, CredentialError: inst.CredentialError,
		}
		if !inst.LastChecked.IsZero() {
			r.LastChecked = inst.LastChecked.Format("01-02 15:04")
		}
		var limit float64
		if inst.TrafficStrategy == "life" {
			limit = inst.LifeTotalLimit
			if limit > 0 {
				r.TrafficPct = inst.TotalTrafficSum / limit * 100
			}
		} else {
			limit = inst.MonthlyLimit
			if limit > 0 {
				r.TrafficPct = inst.CurrentMonthTraffic / limit * 100
			}
		}
		result[i] = r
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"instances": result,
		"summary": gin.H{
			"total":         len(instances),
			"online":        online,
			"stopped":       stopped,
			"total_traffic": totalTraffic,
			"total_cost":    totalCost,
		},
	})
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

	var countVal, errorsVal int64

	if body.Action == "check" {
		var wg sync.WaitGroup
		for _, inst := range instances {
			wg.Add(1)
			go func(id uint) {
				defer wg.Done()
				if err := service.CheckAndManageInstance(id); err != nil {
					atomic.AddInt64(&errorsVal, 1)
				} else {
					atomic.AddInt64(&countVal, 1)
				}
			}(inst.ID)
		}
		wg.Wait()
	} else {
		for _, inst := range instances {
			switch body.Action {
			case "start":
				if inst.Status == "Stopped" {
					ok, _ := service.ECSAction(inst.ID, "start")
					if ok {
						atomic.AddInt64(&countVal, 1)
					} else {
						atomic.AddInt64(&errorsVal, 1)
					}
				}
			case "stop":
				if inst.Status == "Running" {
					ok, _ := service.ECSAction(inst.ID, "stop")
					if ok {
						atomic.AddInt64(&countVal, 1)
					} else {
						atomic.AddInt64(&errorsVal, 1)
					}
				}
			case "delete":
				database.DB.Delete(&inst)
				logOperation("batch_delete", fmt.Sprintf("批量移除实例 %s", inst.Name), nil, c)
				atomic.AddInt64(&countVal, 1)
			}
		}
	}
	count := int(countVal)
	errors := int(errorsVal)

	actionNames := map[string]string{"start": "启动", "stop": "停止", "check": "检查", "delete": "移除"}
	msg := fmt.Sprintf("已对 %d 个实例执行 %s 操作", count, actionNames[body.Action])
	if errors > 0 {
		msg += fmt.Sprintf("，%d 个失败", errors)
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": msg,
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
