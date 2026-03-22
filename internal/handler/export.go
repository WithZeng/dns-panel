package handler

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
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
