package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/gin-gonic/gin"
)

func AddInstancePage(c *gin.Context) {
	c.HTML(http.StatusOK, "add_instance.html", gin.H{
		"username":    c.GetString("username"),
		"role":        c.GetString("role"),
		"instance_id": c.Query("instance_id"),
		"region_id":   c.Query("region_id"),
		"name":        c.Query("name"),
	})
}

func AddInstancePost(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("name"))
	ak := strings.TrimSpace(c.PostForm("access_key_id"))
	sk := strings.TrimSpace(c.PostForm("access_key_secret"))
	regionID := strings.TrimSpace(c.PostForm("region_id"))
	instanceID := strings.TrimSpace(c.PostForm("instance_id"))
	strategy := c.PostForm("traffic_strategy")

	if name == "" || ak == "" || sk == "" || regionID == "" || instanceID == "" {
		c.HTML(http.StatusOK, "add_instance.html", gin.H{"error": "所有必填字段不能为空"})
		return
	}

	encAK, _ := crypto.Encrypt(ak)
	encSK, _ := crypto.Encrypt(sk)

	monthlyLimit, _ := strconv.ParseFloat(c.PostForm("monthly_limit"), 64)
	lifeTotalLimit, _ := strconv.ParseFloat(c.PostForm("life_total_limit"), 64)
	threshold, _ := strconv.Atoi(c.PostForm("alert_threshold_pct"))
	if threshold == 0 {
		threshold = 80
	}

	inst := models.EcsInstance{
		Name:              name,
		AccessKeyID:       encAK,
		AccessKeySK:       encSK,
		IsEncrypted:       true,
		RegionID:          regionID,
		InstanceID:        instanceID,
		TrafficStrategy:   strategy,
		MonthlyLimit:      monthlyLimit,
		LifeTotalLimit:    lifeTotalLimit,
		AlertThresholdPct: threshold,
		Tag:               strings.TrimSpace(c.PostForm("tag")),
		Notes:             strings.TrimSpace(c.PostForm("notes")),
		MonitorEnabled:    c.PostForm("monitoring_enabled") == "on",
		AutoStartEnabled:  c.PostForm("auto_start_enabled") == "on",
		AutoStopEnabled:   c.PostForm("auto_stop_enabled") == "on",
		LastChecked:       time.Now(),
	}

	if err := database.DB.Create(&inst).Error; err != nil {
		c.HTML(http.StatusOK, "add_instance.html", gin.H{"error": fmt.Sprintf("添加失败: %v", err)})
		return
	}

	logOperation("add", fmt.Sprintf("添加实例 %s (%s)", name, instanceID), &inst.ID, c)

	go service.CheckAndManageInstance(inst.ID)

	c.Redirect(http.StatusFound, "/dashboard")
}

func EditInstancePage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.HTML(http.StatusOK, "edit_instance.html", gin.H{
		"instance": inst,
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
	})
}

func EditInstancePost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	inst.Name = strings.TrimSpace(c.PostForm("name"))
	inst.RegionID = strings.TrimSpace(c.PostForm("region_id"))
	inst.InstanceID = strings.TrimSpace(c.PostForm("instance_id"))
	inst.TrafficStrategy = c.PostForm("traffic_strategy")
	inst.MonthlyLimit, _ = strconv.ParseFloat(c.PostForm("monthly_limit"), 64)
	inst.LifeTotalLimit, _ = strconv.ParseFloat(c.PostForm("life_total_limit"), 64)
	inst.AlertThresholdPct, _ = strconv.Atoi(c.PostForm("alert_threshold_pct"))
	inst.Tag = strings.TrimSpace(c.PostForm("tag"))
	inst.Notes = strings.TrimSpace(c.PostForm("notes"))
	inst.MonitorEnabled = c.PostForm("monitoring_enabled") == "on"
	inst.AutoStartEnabled = c.PostForm("auto_start_enabled") == "on"
	inst.AutoStopEnabled = c.PostForm("auto_stop_enabled") == "on"

	if newAK := strings.TrimSpace(c.PostForm("access_key_id")); newAK != "" {
		newSK := strings.TrimSpace(c.PostForm("access_key_secret"))
		encAK, _ := crypto.Encrypt(newAK)
		encSK, _ := crypto.Encrypt(newSK)
		inst.AccessKeyID = encAK
		inst.AccessKeySK = encSK
		inst.IsEncrypted = true
		inst.CredentialStatus = "ok"
		inst.CredentialError = ""
		inst.CredentialLastFailedAt = nil
	}

	database.DB.Save(&inst)
	logOperation("edit", fmt.Sprintf("编辑实例 %s", inst.Name), &inst.ID, c)
	c.Redirect(http.StatusFound, fmt.Sprintf("/instance/%d", inst.ID))
}

func InstanceDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	var logs []models.OperationLog
	database.DB.Where("instance_id = ?", id).Order("timestamp DESC").Limit(50).Find(&logs)

	token := generateIPv6ScriptToken(id)
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	scriptURL := fmt.Sprintf("%s://%s/public/instance/%d/ipv6_script.sh?token=%s", scheme, c.Request.Host, id, token)
	curlCommand := fmt.Sprintf("curl -fsSL '%s' | sudo bash", scriptURL)

	data := gin.H{
		"instance":                      inst,
		"logs":                          logs,
		"username":                      c.GetString("username"),
		"role":                          c.GetString("role"),
		"ipv6_script_url":               scriptURL,
		"ipv6_curl_command":             curlCommand,
		"ipv6_script_token_expires_min": 30,
	}

	if c.GetString("role") == "admin" {
		decAK, _ := crypto.Decrypt(inst.AccessKeyID)
		decSK, _ := crypto.Decrypt(inst.AccessKeySK)
		decLoginAcct, _ := crypto.Decrypt(inst.LoginAccount)
		decLoginPwd, _ := crypto.Decrypt(inst.LoginPassword)
		data["decryptedAK"] = decAK
		data["decryptedSK"] = decSK
		data["loginAccount"] = decLoginAcct
		data["loginPassword"] = decLoginPwd
	}

	c.HTML(http.StatusOK, "instance_detail.html", data)
}

func DeleteInstance(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "实例不存在"})
		return
	}
	name := inst.Name
	database.DB.Delete(&inst)
	logOperation("delete", fmt.Sprintf("删除实例 %s", name), nil, c)
	c.Redirect(http.StatusFound, "/dashboard")
}

func UpdateNotes(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "实例不存在"})
		return
	}
	var body struct {
		Notes string `json:"notes"`
	}
	c.BindJSON(&body)
	inst.Notes = body.Notes
	database.DB.Save(&inst)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func UpdateTrafficSettings(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "实例不存在"})
		return
	}
	var body struct {
		TrafficStrategy   string  `json:"traffic_strategy"`
		MonthlyLimit      float64 `json:"monthly_limit"`
		LifeTotalLimit    float64 `json:"life_total_limit"`
		AlertThresholdPct int     `json:"alert_threshold_pct"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "参数错误"})
		return
	}

	role := c.GetString("role")
	if role == "admin" {
		if body.TrafficStrategy != "" {
			inst.TrafficStrategy = body.TrafficStrategy
		}
		inst.MonthlyLimit = body.MonthlyLimit
		inst.LifeTotalLimit = body.LifeTotalLimit
	}

	if body.AlertThresholdPct > 0 {
		inst.AlertThresholdPct = body.AlertThresholdPct
	}

	database.DB.Save(&inst)
	logOperation("update_traffic", fmt.Sprintf("更新流量设置 %s", inst.Name), &inst.ID, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "设置已更新"})
}

func logOperation(action, detail string, instanceID *uint, c *gin.Context) {
	username, _ := c.Get("username")
	op := models.OperationLog{
		InstanceID: instanceID,
		Action:     action,
		Detail:     detail,
		Operator:   fmt.Sprintf("%v", username),
		Timestamp:  time.Now(),
	}
	database.DB.Create(&op)
}
