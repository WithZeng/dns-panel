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
	"github.com/gin-gonic/gin"
)

func AddInstancePage(c *gin.Context) {
	c.HTML(http.StatusOK, "add_instance.html", gin.H{})
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
	hourlyPrice, _ := strconv.ParseFloat(c.PostForm("hourly_price"), 64)
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
		HourlyPrice:       hourlyPrice,
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
	c.Redirect(http.StatusFound, "/dashboard")
}

func EditInstancePage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.HTML(http.StatusOK, "edit_instance.html", gin.H{"instance": inst})
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
	inst.HourlyPrice, _ = strconv.ParseFloat(c.PostForm("hourly_price"), 64)
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

	c.HTML(http.StatusOK, "instance_detail.html", gin.H{
		"instance": inst,
		"logs":     logs,
	})
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
