package handler

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func ImportCSVPage(c *gin.Context) {
	c.HTML(http.StatusOK, "import_csv.html", gin.H{"username": c.GetString("username")})
}

func ImportCSVPost(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil || !strings.HasSuffix(file.Filename, ".csv") {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "请上传 CSV 文件",
			"username": c.GetString("username"),
		})
		return
	}

	f, err := file.Open()
	if err != nil {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "文件打开失败",
			"username": c.GetString("username"),
		})
		return
	}
	defer f.Close()

	reader := csv.NewReader(f)
	headers, err := reader.Read()
	if err != nil {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "CSV 格式错误",
			"username": c.GetString("username"),
		})
		return
	}

	headerIdx := map[string]int{}
	for i, h := range headers {
		headerIdx[strings.TrimSpace(strings.ToLower(h))] = i
	}

	getField := func(row []string, name string) string {
		idx, ok := headerIdx[name]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	imported, skipped := 0, 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			skipped++
			continue
		}

		instanceID := getField(row, "instance_id")
		if instanceID == "" {
			skipped++
			continue
		}

		var existing models.EcsInstance
		if database.DB.Where("instance_id = ?", instanceID).First(&existing).Error == nil {
			skipped++
			continue
		}

		monthlyLimit, _ := strconv.ParseFloat(getField(row, "monthly_limit"), 64)
		lifeTotalLimit, _ := strconv.ParseFloat(getField(row, "life_total_limit"), 64)
		alertPct, _ := strconv.Atoi(getField(row, "alert_threshold_pct"))
		if alertPct == 0 {
			alertPct = 80
		}

		strategy := getField(row, "traffic_strategy")
		if strategy == "" {
			strategy = "cycle"
		}

		inst := models.EcsInstance{
			Name:              getField(row, "name"),
			RegionID:          getField(row, "region_id"),
			InstanceID:        instanceID,
			Tag:               getField(row, "tag"),
			Notes:             getField(row, "notes"),
			TrafficStrategy:   strategy,
			MonthlyLimit:      monthlyLimit,
			LifeTotalLimit:    lifeTotalLimit,
			AlertThresholdPct: alertPct,
			MonitorEnabled:    true,
		}
		if inst.Name == "" {
			inst.Name = instanceID
		}
		if inst.RegionID == "" {
			inst.RegionID = "cn-hangzhou"
		}

		ak := getField(row, "access_key_id")
		sk := getField(row, "access_key_secret")
		if ak != "" && sk != "" {
			inst.AccessKeyID, _ = crypto.Encrypt(ak)
			inst.AccessKeySK, _ = crypto.Encrypt(sk)
		}

		database.DB.Create(&inst)
		imported++
	}

	c.HTML(http.StatusOK, "import_csv.html", gin.H{
		"flash":    fmt.Sprintf("导入完成：成功 %d，跳过 %d", imported, skipped),
		"username": c.GetString("username"),
	})
}
