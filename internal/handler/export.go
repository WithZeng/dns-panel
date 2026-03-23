package handler

import (
	"archive/zip"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ExportCSV(c *gin.Context) {
	idsParam := c.Query("ids")

	var instances []models.EcsInstance
	if idsParam != "" {
		var ids []int
		for _, s := range strings.Split(idsParam, ",") {
			if id, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				ids = append(ids, id)
			}
		}
		database.DB.Where("id IN ?", ids).Order("tag, name").Find(&instances)
	} else {
		database.DB.Order("tag, name").Find(&instances)
	}

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=instances_%s.csv", time.Now().Format("20060102_1504")))
	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM

	w := csv.NewWriter(c.Writer)
	w.Write([]string{
		"name", "instance_id", "region_id", "access_key_id", "access_key_secret",
		"tag", "notes", "traffic_strategy", "monthly_limit", "life_total_limit",
		"monthly_free_allowance", "alert_threshold_pct",
		"auto_stop_enabled", "auto_start_enabled",
		"total_traffic_sum", "current_month_traffic",
		"status", "public_ip", "private_ip", "ipv6_addr",
	})

	for _, inst := range instances {
		ak, sk := "", ""
		if inst.AccessKeyID != "" {
			decAK, errAK := crypto.Decrypt(inst.AccessKeyID)
			decSK, errSK := crypto.Decrypt(inst.AccessKeySK)
			if errAK == nil && errSK == nil {
				ak, sk = decAK, decSK
			}
		}

		w.Write([]string{
			inst.Name,
			inst.InstanceID,
			inst.RegionID,
			ak,
			sk,
			inst.Tag,
			inst.Notes,
			inst.TrafficStrategy,
			fmt.Sprintf("%.2f", inst.MonthlyLimit),
			fmt.Sprintf("%.2f", inst.LifeTotalLimit),
			fmt.Sprintf("%.2f", inst.MonthlyFreeAllow),
			strconv.Itoa(inst.AlertThresholdPct),
			strconv.FormatBool(inst.AutoStopEnabled),
			strconv.FormatBool(inst.AutoStartEnabled),
			fmt.Sprintf("%.2f", inst.TotalTrafficSum),
			fmt.Sprintf("%.2f", inst.CurrentMonthTraffic),
			inst.Status,
			inst.PublicIP,
			inst.PrivateIP,
			inst.IPv6Addr,
		})
	}
	w.Flush()
}

func DownloadBackup(c *gin.Context) {
	dbPath := os.Getenv("DNS_PANEL_DB_PATH")
	if dbPath == "" {
		dbPath = "data/panel.db"
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "数据库文件不存在"})
		return
	}

	keyPath := "data/encrypt.key"
	hasKey := false
	if _, err := os.Stat(keyPath); err == nil {
		hasKey = true
	}

	timestamp := time.Now().Format("20060102_1504")
	filename := fmt.Sprintf("backup_%s.zip", timestamp)

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	zw := zip.NewWriter(c.Writer)
	defer zw.Close()

	dbData, err := os.ReadFile(dbPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "读取数据库失败"})
		return
	}
	dbEntry, _ := zw.Create("panel.db")
	dbEntry.Write(dbData)

	if hasKey {
		keyData, err := os.ReadFile(keyPath)
		if err == nil {
			keyEntry, _ := zw.Create("encrypt.key")
			keyEntry.Write(keyData)
		}
	}
}

func DownloadBackupPlaintext(c *gin.Context) {
	dbPath := os.Getenv("DNS_PANEL_DB_PATH")
	if dbPath == "" {
		dbPath = "data/panel.db"
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "数据库文件不存在"})
		return
	}

	tmpFile, err := os.CreateTemp("", "panel_plaintext_*.db")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "创建临时文件失败"})
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	srcFile, err := os.Open(dbPath)
	if err != nil {
		tmpFile.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "读取数据库失败"})
		return
	}
	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		srcFile.Close()
		tmpFile.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "复制数据库失败"})
		return
	}
	srcFile.Close()
	tmpFile.Close()

	tmpDB, err := gorm.Open(sqlite.Open(tmpPath+"?_journal_mode=DELETE&_busy_timeout=5000"), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "打开临时数据库失败"})
		return
	}

	var instances []models.EcsInstance
	tmpDB.Find(&instances)
	for _, inst := range instances {
		if inst.AccessKeyID == "" {
			continue
		}
		ak, errAK := crypto.Decrypt(inst.AccessKeyID)
		sk, errSK := crypto.Decrypt(inst.AccessKeySK)
		if errAK != nil || errSK != nil {
			continue
		}
		tmpDB.Model(&models.EcsInstance{}).Where("id = ?", inst.ID).Updates(map[string]interface{}{
			"access_key_id":     ak,
			"access_key_secret": sk,
			"is_encrypted":      false,
		})
	}

	sqlDB, _ := tmpDB.DB()
	tmpDB.Exec("VACUUM")
	sqlDB.Close()

	timestamp := time.Now().Format("20060102_1504")
	filename := fmt.Sprintf("panel_plaintext_%s.db", timestamp)

	c.Header("Content-Type", "application/x-sqlite3")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.File(tmpPath)
}

func APITrafficHistory(c *gin.Context) {
	id := c.Param("id")
	var logs []models.TrafficLog
	database.DB.Where("instance_id = ?", id).Order("timestamp").Limit(500).Find(&logs)

	labels := make([]string, len(logs))
	data := make([]float64, len(logs))
	for i, l := range logs {
		labels[i] = l.Timestamp.Format("01/02 15:04")
		data[i] = l.TrafficGB
	}
	c.JSON(http.StatusOK, gin.H{"labels": labels, "data": data})
}

func APITrafficForecast(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"has_forecast": false})
		return
	}

	var logs []models.TrafficLog
	database.DB.Where("instance_id = ?", id).Order("timestamp asc").Find(&logs)

	if len(logs) < 2 {
		c.JSON(http.StatusOK, gin.H{"has_forecast": false, "message": "历史数据不足，至少需要 2 条记录"})
		return
	}

	cutoff := time.Now().AddDate(0, 0, -7)
	var recent []models.TrafficLog
	for _, l := range logs {
		if l.Timestamp.After(cutoff) {
			recent = append(recent, l)
		}
	}
	if len(recent) < 2 {
		start := len(logs) - 10
		if start < 0 {
			start = 0
		}
		recent = logs[start:]
	}

	first := recent[0]
	last := recent[len(recent)-1]
	hours := last.Timestamp.Sub(first.Timestamp).Hours()
	if hours < 1 {
		hours = 1
	}
	diff := last.TrafficGB - first.TrafficGB
	if diff <= 0 {
		c.JSON(http.StatusOK, gin.H{"has_forecast": false, "message": "流量无增长趋势，无法预测"})
		return
	}

	gbPerDay := (diff / hours) * 24

	var remain float64
	if inst.TrafficStrategy == "life" {
		remain = inst.LifeTotalLimit - inst.TotalTrafficSum
	} else {
		remain = inst.MonthlyLimit - inst.CurrentMonthTraffic
	}
	if remain < 0 {
		remain = 0
	}

	if remain <= 0 {
		c.JSON(http.StatusOK, gin.H{
			"has_forecast": true, "exhausted": true,
			"message": "流量已用尽", "daily_rate": math.Round(gbPerDay*100) / 100,
		})
		return
	}

	daysRemaining := remain / gbPerDay
	exhaustDate := time.Now().AddDate(0, 0, int(daysRemaining)).Format("2006-01-02")

	c.JSON(http.StatusOK, gin.H{
		"has_forecast":   true,
		"exhausted":      false,
		"daily_rate":     math.Round(gbPerDay*100) / 100,
		"days_remaining": math.Round(daysRemaining*10) / 10,
		"exhaust_date":   exhaustDate,
		"message":        fmt.Sprintf("按当前速率（%.2f GB/天），预计 %s 用尽配额", gbPerDay, exhaustDate),
	})
}

func APICDTThreeMonths(c *gin.Context) {
	instanceIDParam := c.Query("instance_id")

	var instances []models.EcsInstance
	if instanceIDParam != "" {
		database.DB.Where("instance_id = ?", instanceIDParam).Find(&instances)
	} else {
		database.DB.Limit(1).Find(&instances)
	}

	if len(instances) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "未找到实例"})
		return
	}

	inst := instances[0]
	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": fmt.Sprintf("凭据解密失败：%s", err.Error())})
		return
	}

	billing, err := aliyun.GetCDTThreeMonthBilling(client, instanceIDParam, inst.RegionID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": fmt.Sprintf("查询 CDT 账单失败：%s", err.Error())})
		return
	}

	months := make([]gin.H, 0)
	if billing.Months != nil {
		for _, m := range billing.Months {
			months = append(months, gin.H{
				"month":        m.Month,
				"traffic":      m.Traffic,
				"amount":       m.Amount,
				"traffic_unit": m.TrafficUnit,
				"currency":     m.Currency,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"months":        months,
		"total_traffic": billing.TotalTraffic,
		"total_amount":  billing.TotalAmount,
		"currency":      billing.Currency,
		"scope":         billing.Scope,
	})
}

func APIRegionTraffic(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Find(&instances)

	type regionInfo struct {
		Region string  `json:"region"`
		Used   float64 `json:"used"`
		Limit  float64 `json:"limit"`
		Count  int     `json:"count"`
	}
	regionMap := map[string]*regionInfo{}

	for _, inst := range instances {
		ri, ok := regionMap[inst.RegionID]
		if !ok {
			ri = &regionInfo{Region: inst.RegionID}
			regionMap[inst.RegionID] = ri
		}
		ri.Count++
		if inst.TrafficStrategy == "life" {
			ri.Used += inst.TotalTrafficSum
			ri.Limit += inst.LifeTotalLimit
		} else {
			ri.Used += inst.CurrentMonthTraffic
			ri.Limit += inst.MonthlyLimit
		}
	}

	result := make([]regionInfo, 0, len(regionMap))
	for _, ri := range regionMap {
		ri.Used = math.Round(ri.Used*100) / 100
		ri.Limit = math.Round(ri.Limit*100) / 100
		result = append(result, *ri)
	}
	c.JSON(http.StatusOK, result)
}
