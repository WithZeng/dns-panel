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
	username := c.GetString("username")
	file, err := c.FormFile("file")
	if err != nil || !strings.HasSuffix(strings.ToLower(file.Filename), ".csv") {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "请上传 CSV 文件",
			"username": username,
		})
		return
	}

	f, err := file.Open()
	if err != nil {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "文件打开失败",
			"username": username,
		})
		return
	}
	defer f.Close()

	reader := csv.NewReader(f)
	headers, err := reader.Read()
	if err != nil {
		c.HTML(http.StatusOK, "import_csv.html", gin.H{
			"error":    "CSV 格式错误",
			"username": username,
		})
		return
	}

	// Strip BOM
	if len(headers) > 0 {
		headers[0] = strings.TrimPrefix(headers[0], "\xef\xbb\xbf")
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

	getFloat := func(row []string, name string, fallback float64) float64 {
		s := getField(row, name)
		if s == "" {
			return fallback
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fallback
		}
		return v
	}

	getInt := func(row []string, name string, fallback int) int {
		s := getField(row, name)
		if s == "" {
			return fallback
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return fallback
		}
		return v
	}

	getBool := func(row []string, name string) bool {
		s := strings.ToLower(getField(row, name))
		return s == "true" || s == "1" || s == "yes"
	}

	imported, updated, skipped := 0, 0, 0
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

		name := getField(row, "name")
		if name == "" {
			name = instanceID
		}
		regionID := getField(row, "region_id")
		if regionID == "" {
			regionID = "cn-hangzhou"
		}
		strategy := getField(row, "traffic_strategy")
		if strategy == "" {
			strategy = "cycle"
		}

		ak := getField(row, "access_key_id")
		sk := getField(row, "access_key_secret")
		encAK, encSK := "", ""
		hasCredentials := false
		if ak != "" && sk != "" {
			encAK, _ = crypto.Encrypt(ak)
			encSK, _ = crypto.Encrypt(sk)
			hasCredentials = true
		} else if (ak != "" && sk == "") || (ak == "" && sk != "") {
			skipped++
			continue
		}

		var existing models.EcsInstance
		if database.DB.Where("instance_id = ?", instanceID).First(&existing).Error == nil {
			existing.Name = name
			existing.RegionID = regionID
			if hasCredentials {
				existing.AccessKeyID = encAK
				existing.AccessKeySK = encSK
				existing.IsEncrypted = true
				existing.CredentialStatus = "ok"
				existing.CredentialError = ""
			}
			existing.Tag = getField(row, "tag")
			existing.Notes = getField(row, "notes")
			existing.TrafficStrategy = strategy
			existing.MonthlyLimit = getFloat(row, "monthly_limit", existing.MonthlyLimit)
			existing.LifeTotalLimit = getFloat(row, "life_total_limit", existing.LifeTotalLimit)
			existing.MonthlyFreeAllow = getFloat(row, "monthly_free_allowance", existing.MonthlyFreeAllow)
			existing.AlertThresholdPct = getInt(row, "alert_threshold_pct", existing.AlertThresholdPct)
			existing.AutoStopEnabled = getBool(row, "auto_stop_enabled")
			existing.AutoStartEnabled = getBool(row, "auto_start_enabled")

			ts := getField(row, "total_traffic_sum")
			if ts != "" {
				existing.TotalTrafficSum = getFloat(row, "total_traffic_sum", 0)
			}
			cmt := getField(row, "current_month_traffic")
			if cmt != "" {
				existing.CurrentMonthTraffic = getFloat(row, "current_month_traffic", 0)
			}

			database.DB.Save(&existing)
			updated++
		} else {
			inst := models.EcsInstance{
				Name:                name,
				RegionID:            regionID,
				InstanceID:          instanceID,
				AccessKeyID:         encAK,
				AccessKeySK:         encSK,
				IsEncrypted:         hasCredentials,
				Tag:                 getField(row, "tag"),
				Notes:               getField(row, "notes"),
				TrafficStrategy:     strategy,
				MonthlyLimit:        getFloat(row, "monthly_limit", 0),
				LifeTotalLimit:      getFloat(row, "life_total_limit", 0),
				MonthlyFreeAllow:    getFloat(row, "monthly_free_allowance", 200),
				AlertThresholdPct:   getInt(row, "alert_threshold_pct", 80),
				AutoStopEnabled:     getBool(row, "auto_stop_enabled"),
				AutoStartEnabled:    getBool(row, "auto_start_enabled"),
				TotalTrafficSum:     getFloat(row, "total_traffic_sum", 0),
				CurrentMonthTraffic: getFloat(row, "current_month_traffic", 0),
				MonitorEnabled:      true,
			}

			s := getField(row, "status")
			if s != "" {
				inst.Status = s
			}
			if ip := getField(row, "public_ip"); ip != "" {
				inst.PublicIP = ip
			}
			if ip := getField(row, "private_ip"); ip != "" {
				inst.PrivateIP = ip
			}
			if ip := getField(row, "ipv6_addr"); ip != "" {
				inst.IPv6Addr = ip
			}

			database.DB.Create(&inst)
			imported++
		}
	}

	msg := fmt.Sprintf("导入完成：新增 %d，更新 %d，跳过 %d", imported, updated, skipped)
	c.HTML(http.StatusOK, "import_csv.html", gin.H{
		"flash":    msg,
		"username": username,
	})
}
