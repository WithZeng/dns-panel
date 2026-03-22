package handler

import (
	"encoding/csv"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

func ExportCSV(c *gin.Context) {
	var instances []models.EcsInstance
	database.DB.Order("tag, name").Find(&instances)

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=instances_%s.csv", time.Now().Format("20060102")))

	w := csv.NewWriter(c.Writer)
	w.Write([]string{"名称", "Instance ID", "地域", "状态", "流量策略", "月流量(GB)", "终身流量(GB)", "公网IP", "标签"})

	for _, inst := range instances {
		w.Write([]string{
			inst.Name,
			inst.InstanceID,
			inst.RegionID,
			inst.Status,
			inst.TrafficStrategy,
			fmt.Sprintf("%.2f", inst.CurrentMonthTraffic),
			fmt.Sprintf("%.2f", inst.TotalTrafficSum),
			inst.PublicIP,
			inst.Tag,
		})
	}
	w.Flush()
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

func DownloadBackup(c *gin.Context) {
	dbPath := os.Getenv("DNS_PANEL_DB_PATH")
	if dbPath == "" {
		dbPath = "data/panel.db"
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "数据库文件不存在"})
		return
	}
	c.FileAttachment(dbPath, "panel_backup.db")
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
