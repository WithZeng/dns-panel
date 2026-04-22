package handler

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

func Dashboard(c *gin.Context) {
	role := c.GetString("role")

	if role != "admin" {
		userDashboard(c)
		return
	}

	var instances []models.EcsInstance
	tag := c.Query("tag")
	q := database.DB.Order("tag, name")
	if tag != "" {
		q = q.Where("tag = ?", tag)
	}
	q.Find(&instances)

	tags := map[string]bool{}
	var totalTraffic float64
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
		"currentTag":   tag,
		"username":     c.GetString("username"),
		"role":         role,
	})
}

func userDashboard(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var assignedIDs []uint
	database.DB.Model(&models.UserInstance{}).
		Where("user_id = ?", userID).
		Pluck("instance_id", &assignedIDs)

	var instances []models.EcsInstance
	if len(assignedIDs) > 0 {
		database.DB.Where("id IN ?", assignedIDs).Order("tag, name").Find(&instances)
	}

	var online, stopped int
	for _, inst := range instances {
		switch inst.Status {
		case "Running", "Starting":
			online++
		case "Stopped":
			stopped++
		}
	}

	c.HTML(http.StatusOK, "user_dashboard.html", gin.H{
		"instances": instances,
		"total":     len(instances),
		"online":    online,
		"stopped":   stopped,
		"username":  c.GetString("username"),
		"role":      c.GetString("role"),
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
		PrivateIP         string  `json:"private_ip"`
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
		CPU               int     `json:"cpu"`
		Memory            int     `json:"memory"`
		Bandwidth         int     `json:"bandwidth"`
		BandwidthType     string  `json:"bandwidth_type"`
		OSType            string  `json:"os_type"`
		CreationTime      string  `json:"creation_time"`
		ExpiredTime       string  `json:"expired_time"`
	}

	var online, stopped int
	var totalTraffic float64
	result := make([]instanceJSON, len(instances))

	for i, inst := range instances {
		if inst.Status == "Running" || inst.Status == "Starting" {
			online++
		} else if inst.Status == "Stopped" {
			stopped++
		}
		totalTraffic += inst.CurrentMonthTraffic

		r := instanceJSON{
			ID: inst.ID, Name: inst.Name, InstanceID: inst.InstanceID,
			RegionID: inst.RegionID, Status: inst.Status, PublicIP: inst.PublicIP,
			PrivateIP: inst.PrivateIP, IPv6Addr: inst.IPv6Addr, Tag: inst.Tag,
			TrafficStrategy: inst.TrafficStrategy,
			CurrentMonthTraffic: inst.CurrentMonthTraffic, MonthlyLimit: inst.MonthlyLimit,
			TotalTrafficSum: inst.TotalTrafficSum, LifeTotalLimit: inst.LifeTotalLimit,
			CredentialStatus: inst.CredentialStatus, CredentialError: inst.CredentialError,
			CPU: inst.CPU, Memory: inst.Memory, Bandwidth: inst.Bandwidth, BandwidthType: inst.BandwidthType,
			OSType: inst.OSType, CreationTime: inst.CreationTime, ExpiredTime: inst.ExpiredTime,
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
		},
	})
}

func BatchAction(c *gin.Context) {
	var body struct {
		Action   string `json:"action"`
		IDs      []uint `json:"ids"`
		Password string `json:"password"`
		ImageID  string `json:"image_id"`
		Name     string `json:"name"`
		Port     string `json:"port"`
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
					if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
				}
			case "stop":
				if inst.Status == "Running" {
					ok, _ := service.ECSAction(inst.ID, "stop")
					if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
				}
			case "reboot":
				if inst.Status == "Running" {
					ok, _ := service.ECSAction(inst.ID, "reboot")
					if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
				}
			case "password":
				if body.Password == "" { continue }
				client, err := getClientForBatch(&inst)
				if err != nil { atomic.AddInt64(&errorsVal, 1); continue }
				ok, _ := aliyun.ECSModifyPassword(client, inst.InstanceID, body.Password)
				if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
			case "reset_system":
				if body.ImageID == "" || inst.Status != "Stopped" { atomic.AddInt64(&errorsVal, 1); continue }
				client, err := getClientForBatch(&inst)
				if err != nil { atomic.AddInt64(&errorsVal, 1); continue }
				ok, _ := aliyun.ECSReplaceSystemDisk(client, inst.InstanceID, body.ImageID)
				if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
			case "rename":
				if body.Name == "" { continue }
				inst.Name = body.Name
				database.DB.Save(&inst)
				atomic.AddInt64(&countVal, 1)
			case "open_port":
				if body.Port == "" { continue }
				client, err := getClientForBatch(&inst)
				if err != nil { atomic.AddInt64(&errorsVal, 1); continue }
				sgIDs, err := aliyun.GetSecurityGroups(client, inst.InstanceID)
				if err != nil || len(sgIDs) == 0 { atomic.AddInt64(&errorsVal, 1); continue }
				ok, _ := aliyun.AuthorizeSG(client, sgIDs[0], "tcp", body.Port+"/"+body.Port, "0.0.0.0/0", "accept", "batch")
				if ok { atomic.AddInt64(&countVal, 1) } else { atomic.AddInt64(&errorsVal, 1) }
			case "delete":
				database.DB.Delete(&inst)
				logOperation("batch_delete", fmt.Sprintf("批量移除实例 %s", inst.Name), nil, c)
				atomic.AddInt64(&countVal, 1)
			}
		}
	}
	count := int(countVal)
	errors := int(errorsVal)

	actionNames := map[string]string{
		"start": "启动", "stop": "关机", "reboot": "重启", "check": "检查",
		"delete": "移除", "password": "改密", "reset_system": "重置系统",
		"rename": "备注", "open_port": "开放端口",
	}
	name := actionNames[body.Action]
	if name == "" { name = body.Action }
	msg := fmt.Sprintf("已对 %d 个实例执行 %s 操作", count, name)
	if errors > 0 {
		msg += fmt.Sprintf("，%d 个失败", errors)
	}
	logOperation("batch_"+body.Action, msg, nil, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": msg})
}

func getClientForBatch(inst *models.EcsInstance) (*aliyun.Client, error) {
	ak, err := decryptField(inst.AccessKeyID)
	if err != nil { return nil, err }
	sk, err := decryptField(inst.AccessKeySK)
	if err != nil { return nil, err }
	return aliyun.NewClient(ak, sk, inst.RegionID), nil
}

func CheckAll(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Where("status != ?", "Released").Find(&instances)
	for _, inst := range instances {
		go service.CheckAndManageInstance(inst.ID)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("已触发检查 %d 个实例", len(instances))})
}

