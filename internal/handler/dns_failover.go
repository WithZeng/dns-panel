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

func DNSFailoverPage(c *gin.Context) {
	var cfgCF models.CloudflareConfig
	database.DB.FirstOrCreate(&cfgCF)

	var rules []models.DnsFailover
	database.DB.Preload("PrimaryServer").Preload("CurrentActiveServer").Find(&rules)

	var probes []models.ProbeServer
	database.DB.Order("name").Find(&probes)

	var logs []models.DnsFailoverLog
	database.DB.Order("created_at DESC").Limit(50).Find(&logs)

	c.HTML(http.StatusOK, "dns_failover.html", gin.H{
		"cf_config": cfgCF,
		"rules":     rules,
		"probes":    probes,
		"logs":      logs,
		"username":  c.GetString("username"),
	})
}

func SaveCloudflareConfig(c *gin.Context) {
	var cfg models.CloudflareConfig
	database.DB.FirstOrCreate(&cfg)

	apiToken := strings.TrimSpace(c.PostForm("api_token"))
	if apiToken != "" && apiToken != "********" {
		encrypted, err := crypto.Encrypt(apiToken)
		if err == nil {
			cfg.APIToken = encrypted
		}
	}
	cfg.ZoneID = strings.TrimSpace(c.PostForm("zone_id"))
	cfg.Domain = strings.TrimSpace(c.PostForm("domain"))
	cfg.TesterIP = strings.TrimSpace(c.PostForm("tester_ip"))
	database.DB.Save(&cfg)

	c.Redirect(http.StatusFound, "/dns_failover")
}

func CreateDNSFailoverRule(c *gin.Context) {
	domain := strings.TrimSpace(c.PostForm("domain"))
	primaryID, _ := strconv.Atoi(c.PostForm("primary_server_id"))
	backupIDsStr := c.PostFormArray("backup_server_ids[]")

	if domain == "" || primaryID == 0 {
		c.Redirect(http.StatusFound, "/dns_failover")
		return
	}

	var backupIDs []uint
	for _, s := range backupIDsStr {
		if id, err := strconv.Atoi(s); err == nil && uint(id) != uint(primaryID) {
			backupIDs = append(backupIDs, uint(id))
		}
	}

	activeID := uint(primaryID)
	rule := models.DnsFailover{
		Domain:                domain,
		PrimaryServerID:       uint(primaryID),
		CurrentActiveServerID: &activeID,
		Enabled:               true,
	}
	rule.SetBackupIDs(backupIDs)
	database.DB.Create(&rule)

	c.Redirect(http.StatusFound, "/dns_failover")
}

func ToggleDNSFailoverRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var rule models.DnsFailover
	if err := database.DB.First(&rule, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dns_failover")
		return
	}
	rule.Enabled = !rule.Enabled
	database.DB.Save(&rule)
	c.Redirect(http.StatusFound, "/dns_failover")
}

func DeleteDNSFailoverRule(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	database.DB.Delete(&models.DnsFailover{}, id)
	database.DB.Where("failover_id = ?", id).Delete(&models.DnsFailoverLog{})
	c.Redirect(http.StatusFound, "/dns_failover")
}

func APIDNSFailoverLogs(c *gin.Context) {
	id := c.Query("failover_id")
	var logs []models.DnsFailoverLog
	q := database.DB.Order("timestamp DESC").Limit(100)
	if id != "" {
		q = q.Where("failover_id = ?", id)
	}
	q.Find(&logs)
	c.JSON(http.StatusOK, gin.H{"success": true, "logs": logs})
}

func APIDNSFailoverTestSwitch(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var rule models.DnsFailover
	if err := database.DB.First(&rule, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}

	var cfgCF models.CloudflareConfig
	if err := database.DB.First(&cfgCF).Error; err != nil || cfgCF.APIToken == "" || cfgCF.ZoneID == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "Cloudflare 配置不完整"})
		return
	}

	apiToken, err := crypto.Decrypt(cfgCF.APIToken)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "解密 API Token 失败"})
		return
	}

	backupIDs := rule.GetBackupIDs()
	if len(backupIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "没有备用服务器"})
		return
	}

	var target models.ProbeServer
	if err := database.DB.First(&target, backupIDs[0]).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "备用服务器不存在"})
		return
	}

	targetIP := target.IPv4
	if targetIP == "" {
		targetIP = target.IPv6
	}
	if targetIP == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "目标服务器无 IP"})
		return
	}

	recordType := "A"
	if strings.Contains(targetIP, ":") {
		recordType = "AAAA"
	}

	cf := service.NewCloudflareManager(apiToken)
	_, err = cf.UpsertDNSRecord(cfgCF.ZoneID, rule.Domain, recordType, targetIP, 120, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	var oldActiveID uint
	if rule.CurrentActiveServerID != nil {
		oldActiveID = *rule.CurrentActiveServerID
	}
	newActiveID := target.ID
	rule.CurrentActiveServerID = &newActiveID
	now := time.Now()
	rule.LastSwitchTime = &now
	database.DB.Save(&rule)

	recordFailoverLog(rule.ID, "manual_test",
		fmt.Sprintf("%s 手动切换到 %s (%s)", rule.Domain, target.Name, targetIP),
		oldActiveID, target.ID)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("已切换到 %s (%s)", target.Name, targetIP)})
}

func recordFailoverLog(failoverID uint, action, message string, fromID, toID uint) {
	entry := models.DnsFailoverLog{
		FailoverID:   &failoverID,
		Action:       action,
		Message:      message,
		FromServerID: &fromID,
		ToServerID:   &toID,
	}
	database.DB.Create(&entry)
}
