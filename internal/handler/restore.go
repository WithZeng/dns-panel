package handler

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func RestorePage(c *gin.Context) {
	data := gin.H{
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
	}
	if f := c.Query("flash"); f != "" {
		data["flash"] = f
	}
	if e := c.Query("error"); e != "" {
		data["error"] = e
	}
	c.HTML(http.StatusOK, "restore.html", data)
}

func RestoreDBPage(c *gin.Context) {
	c.HTML(http.StatusOK, "restore_db.html", gin.H{
		"username": c.GetString("username"),
		"role":     c.GetString("role"),
	})
}

func RestoreDBPost(c *gin.Context) {
	username := c.GetString("username")
	fernetKey := c.PostForm("fernet_key")
	skipCreds := c.PostForm("skip_credentials") == "1"
	redirectTo := c.PostForm("redirect")

	renderOrRedirect := func(flash, errMsg string) {
		if redirectTo != "" {
			sep := "?"
			if strings.Contains(redirectTo, "?") {
				sep = "&"
			}
			if errMsg != "" {
				c.Redirect(http.StatusFound, redirectTo+sep+"error="+url.QueryEscape(errMsg))
			} else {
				c.Redirect(http.StatusFound, redirectTo+sep+"flash="+url.QueryEscape(flash))
			}
			return
		}
		data := gin.H{
			"username": username,
			"role":     c.GetString("role"),
		}
		if errMsg != "" {
			data["error"] = errMsg
		}
		if flash != "" {
			data["flash"] = flash
		}
		c.HTML(http.StatusOK, "restore_db.html", data)
	}

	file, _, err := c.Request.FormFile("db_file")
	if err != nil {
		renderOrRedirect("", "请选择数据库文件")
		return
	}
	defer file.Close()

	tmpPath := os.TempDir() + "/dns_panel_restore.db"
	out, err := os.Create(tmpPath)
	if err != nil {
		renderOrRedirect("", "创建临时文件失败")
		return
	}
	written, _ := io.Copy(out, file)
	out.Close()
	defer os.Remove(tmpPath)

	if written < 100 {
		renderOrRedirect("", "文件过小，不是有效的数据库")
		return
	}

	header := make([]byte, 16)
	f, _ := os.Open(tmpPath)
	if f != nil {
		f.Read(header)
		f.Close()
	}
	if string(header[:13]) != "SQLite format" {
		renderOrRedirect("", "无效的 SQLite 数据库文件")
		return
	}

	srcDB, err := gorm.Open(sqlite.Open(tmpPath+"?mode=ro"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		renderOrRedirect("", "无法打开上传的数据库："+err.Error())
		return
	}
	sqlDB, _ := srcDB.DB()
	defer sqlDB.Close()

	type srcInstance struct {
		Name                string  `gorm:"column:name"`
		InstanceID          string  `gorm:"column:instance_id"`
		RegionID            string  `gorm:"column:region_id"`
		AccessKeyID         string  `gorm:"column:access_key_id"`
		AccessKeySK         string  `gorm:"column:access_key_secret"`
		IsEncrypted         bool    `gorm:"column:is_encrypted"`
		TrafficStrategy     string  `gorm:"column:traffic_strategy"`
		MonthlyLimit        float64 `gorm:"column:monthly_limit"`
		LifeTotalLimit      float64 `gorm:"column:life_total_limit"`
		MonthlyFreeAllow    float64 `gorm:"column:monthly_free_allowance"`
		TotalTrafficSum     float64 `gorm:"column:total_traffic_sum"`
		CurrentMonthTraffic float64 `gorm:"column:current_month_traffic"`
		LastAPITraffic      float64 `gorm:"column:last_api_traffic"`
		AlertThresholdPct   int     `gorm:"column:alert_threshold_pct"`
		Tag                 string  `gorm:"column:tag"`
		Notes               string  `gorm:"column:notes"`
		Status              string  `gorm:"column:status"`
		PublicIP            string  `gorm:"column:public_ip"`
		PrivateIP           string  `gorm:"column:private_ip"`
		IPv6Addr            string  `gorm:"column:ipv6_addr"`
		AutoStopEnabled     bool    `gorm:"column:auto_stop_enabled"`
		AutoStartEnabled    bool    `gorm:"column:auto_start_enabled"`
		MonitorEnabled      bool    `gorm:"column:monitor_enabled"`
	}

	var srcInstances []srcInstance
	if err := srcDB.Table("ecs_instance").Find(&srcInstances).Error; err != nil {
		renderOrRedirect("", "读取实例数据失败："+err.Error())
		return
	}

	if len(srcInstances) == 0 {
		renderOrRedirect("", "上传的数据库中没有实例数据")
		return
	}

	hasFernet := false
	for _, s := range srcInstances {
		if crypto.IsFernetToken(s.AccessKeyID) || crypto.IsFernetToken(s.AccessKeySK) {
			hasFernet = true
			break
		}
	}

	if hasFernet && fernetKey == "" && !skipCreds {
		if redirectTo != "" {
			renderOrRedirect("", "数据库包含加密凭据，请使用原始恢复页面并提供 Fernet 密钥")
			return
		}
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username":       username,
			"role":           c.GetString("role"),
			"need_fernet":    true,
			"instance_count": len(srcInstances),
		})
		return
	}

	reencrypt := func(ciphertext string) (string, error) {
		if ciphertext == "" {
			return "", nil
		}
		if skipCreds && crypto.IsFernetToken(ciphertext) {
			return "", nil
		}
		if crypto.IsFernetToken(ciphertext) {
			if fernetKey == "" {
				return "", fmt.Errorf("missing fernet key")
			}
			plain, err := crypto.DecryptFernet(ciphertext, fernetKey)
			if err != nil {
				return "", fmt.Errorf("fernet decrypt: %w", err)
			}
			return crypto.Encrypt(plain)
		}
		if _, err := crypto.Decrypt(ciphertext); err == nil {
			return ciphertext, nil
		}
		return crypto.Encrypt(ciphertext)
	}

	imported, updated, credErrors, skippedCreds := 0, 0, 0, 0
	for _, s := range srcInstances {
		newAK, errAK := reencrypt(s.AccessKeyID)
		newSK, errSK := reencrypt(s.AccessKeySK)
		if errAK != nil || errSK != nil {
			credErrors++
			log.Printf("[restore] credential re-encrypt failed for %s: AK=%v SK=%v", s.InstanceID, errAK, errSK)
			newAK = ""
			newSK = ""
		}
		if skipCreds && (crypto.IsFernetToken(s.AccessKeyID) || crypto.IsFernetToken(s.AccessKeySK)) {
			skippedCreds++
		}

		var existing models.EcsInstance
		if database.DB.Where("instance_id = ?", s.InstanceID).First(&existing).Error == nil {
			existing.Name = s.Name
			existing.RegionID = s.RegionID
			if newAK != "" {
				existing.AccessKeyID = newAK
				existing.AccessKeySK = newSK
				existing.IsEncrypted = true
				existing.CredentialStatus = "ok"
				existing.CredentialError = ""
			}
			existing.TrafficStrategy = s.TrafficStrategy
			existing.MonthlyLimit = s.MonthlyLimit
			existing.LifeTotalLimit = s.LifeTotalLimit
			existing.MonthlyFreeAllow = s.MonthlyFreeAllow
			existing.TotalTrafficSum = s.TotalTrafficSum
			existing.CurrentMonthTraffic = s.CurrentMonthTraffic
			existing.LastAPITraffic = s.LastAPITraffic
			existing.AlertThresholdPct = s.AlertThresholdPct
			existing.Tag = s.Tag
			existing.Notes = s.Notes
			existing.Status = s.Status
			existing.PublicIP = s.PublicIP
			existing.PrivateIP = s.PrivateIP
			existing.IPv6Addr = s.IPv6Addr
			existing.AutoStopEnabled = s.AutoStopEnabled
			existing.AutoStartEnabled = s.AutoStartEnabled
			existing.MonitorEnabled = s.MonitorEnabled
			database.DB.Save(&existing)
			updated++
		} else {
			inst := models.EcsInstance{
				Name:                s.Name,
				InstanceID:          s.InstanceID,
				RegionID:            s.RegionID,
				AccessKeyID:         newAK,
				AccessKeySK:         newSK,
				IsEncrypted:         true,
				TrafficStrategy:     s.TrafficStrategy,
				MonthlyLimit:        s.MonthlyLimit,
				LifeTotalLimit:      s.LifeTotalLimit,
				MonthlyFreeAllow:    s.MonthlyFreeAllow,
				TotalTrafficSum:     s.TotalTrafficSum,
				CurrentMonthTraffic: s.CurrentMonthTraffic,
				LastAPITraffic:      s.LastAPITraffic,
				AlertThresholdPct:   s.AlertThresholdPct,
				Tag:                 s.Tag,
				Notes:               s.Notes,
				Status:              s.Status,
				PublicIP:            s.PublicIP,
				PrivateIP:           s.PrivateIP,
				IPv6Addr:            s.IPv6Addr,
				AutoStopEnabled:     s.AutoStopEnabled,
				AutoStartEnabled:    s.AutoStartEnabled,
				MonitorEnabled:      s.MonitorEnabled,
			}
			if inst.AlertThresholdPct == 0 {
				inst.AlertThresholdPct = 80
			}
			database.DB.Create(&inst)
			imported++
		}
	}

	log.Printf("[restore] Imported %d, updated %d, credential errors %d", imported, updated, credErrors)

	msg := fmt.Sprintf("导入完成！新增 %d 个实例，更新 %d 个实例。", imported, updated)
	if skippedCreds > 0 {
		msg += fmt.Sprintf(" 已跳过 %d 个实例的凭据，请通过「账户导入」重新扫描补充 AK/SK。", skippedCreds)
	}
	if credErrors > 0 {
		msg += fmt.Sprintf(" 其中 %d 个实例凭据转换失败（密钥可能不正确），需要手动重新填写 AK/SK。", credErrors)
	}

	renderOrRedirect(msg, "")
}
