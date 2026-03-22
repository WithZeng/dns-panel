package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

var allAliyunRegions = []string{
	"cn-beijing", "cn-zhangjiakou", "cn-huhehaote", "cn-wulanchabu",
	"cn-hangzhou", "cn-shanghai", "cn-nanjing", "cn-fuzhou",
	"cn-shenzhen", "cn-heyuan", "cn-guangzhou", "cn-chengdu",
	"cn-hongkong",
	"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-5",
	"ap-southeast-6", "ap-southeast-7", "ap-northeast-1", "ap-northeast-2",
	"ap-south-1",
	"us-east-1", "us-west-1", "eu-west-1", "eu-central-1",
	"me-east-1", "me-central-1",
}

func ImportAccountTextPage(c *gin.Context) {
	doneJobID := c.Query("job_done")
	if doneJobID != "" {
		var job models.ImportJob
		if database.DB.First(&job, "id = ?", doneJobID).Error == nil && job.Status == "done" {
			result := job.GetResult()
			c.HTML(http.StatusOK, "import_account_text.html", gin.H{
				"username": c.GetString("username"),
				"result":   result,
			})
			return
		}
	}
	c.HTML(http.StatusOK, "import_account_text.html", gin.H{"username": c.GetString("username")})
}

func ImportAccountTextPost(c *gin.Context) {
	rawText := c.PostForm("account_text")
	if strings.TrimSpace(rawText) == "" {
		c.HTML(http.StatusOK, "import_account_text.html", gin.H{
			"username": c.GetString("username"),
			"error":    "请粘贴账号文本",
			"raw_text": rawText,
		})
		return
	}
	if len(rawText) > 10000 {
		rawText = rawText[:10000]
	}

	scanAll := c.PostForm("scan_all_regions") == "1"

	jobID := fmt.Sprintf("imp-%d", time.Now().UnixNano()%1000000000)
	job := models.ImportJob{
		ID:      jobID,
		Status:  "running",
		Step:    "解析文本",
		Message: "正在解析账号信息...",
	}
	database.DB.Create(&job)

	go runAccountImport(jobID, rawText, scanAll)

	c.HTML(http.StatusOK, "import_account_text.html", gin.H{
		"username": c.GetString("username"),
		"raw_text": rawText,
		"job_id":   jobID,
	})
}

func ImportAccountTextStatus(c *gin.Context) {
	jobID := c.Param("job_id")
	var job models.ImportJob
	if err := database.DB.First(&job, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "任务不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"job": gin.H{
			"id":       job.ID,
			"status":   job.Status,
			"step":     job.Step,
			"message":  job.Message,
			"progress": job.Progress,
			"error":    job.Error,
		},
	})
}

func parseAccountText(text string) map[string]string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")

	keyMap := map[string][]string{
		"access_key_id":     {"accesskey id", "access key id", "accesskeyid", "key id", "akid", "ak"},
		"access_key_secret": {"accesskey secret", "access key secret", "accesskeysecret", "secret key", "sk"},
		"login_name":        {"登录名称", "登录名", "账号", "账户", "用户名", "login name", "username", "account"},
		"remark":            {"备注", "说明", "note", "notes", "remark", "memo"},
		"region_id":         {"区域", "地域", "region id", "region_id", "region"},
	}

	parsed := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		normalized := strings.ReplaceAll(line, "：", ":")
		idx := strings.Index(normalized, ":")
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(normalized[:idx])
		right := strings.TrimSpace(normalized[idx+1:])
		if right == "" {
			continue
		}
		keyLow := strings.ToLower(left)
		keyNoSpace := removeSpaces(keyLow)

		for target, aliases := range keyMap {
			matched := false
			for _, alias := range aliases {
				aliasNoSpace := removeSpaces(alias)
				if keyLow == alias || keyNoSpace == aliasNoSpace || strings.Contains(keyLow, alias) {
					matched = true
					break
				}
			}
			if matched {
				parsed[target] = right
				break
			}
		}
	}

	ak := strings.TrimSpace(parsed["access_key_id"])
	sk := strings.TrimSpace(parsed["access_key_secret"])

	if ak == "" {
		re := regexp.MustCompile(`\b(LTAI[a-zA-Z0-9]{8,})\b`)
		m := re.FindString(text)
		if m != "" {
			ak = m
		}
	}
	if sk == "" {
		re := regexp.MustCompile(`\b[a-zA-Z0-9+/=]{24,64}\b`)
		candidates := re.FindAllString(text, -1)
		for _, c := range candidates {
			if c != ak && !strings.HasPrefix(c, "LTAI") {
				sk = c
				break
			}
		}
	}

	parsed["access_key_id"] = ak
	parsed["access_key_secret"] = sk

	regionID := strings.TrimSpace(parsed["region_id"])
	if regionID == "" || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(regionID) {
		regionID = "cn-hangzhou"
	}
	parsed["region_id"] = regionID

	return parsed
}

func removeSpaces(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func slugifyAccount(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	re := regexp.MustCompile(`[^a-z0-9\p{Han}-]+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func runAccountImport(jobID, rawText string, scanAll bool) {
	updateJob := func(step, message string, progress int) {
		database.DB.Model(&models.ImportJob{}).Where("id = ?", jobID).Updates(map[string]interface{}{
			"step": step, "message": message, "progress": progress, "updated_at": time.Now(),
		})
	}
	failJob := func(msg, errType string) {
		now := time.Now()
		database.DB.Model(&models.ImportJob{}).Where("id = ?", jobID).Updates(map[string]interface{}{
			"status": "error", "message": msg, "error": errType,
			"finished_at": &now, "updated_at": now,
		})
	}
	doneJob := func(result map[string]interface{}) {
		now := time.Now()
		data, _ := json.Marshal(result)
		database.DB.Model(&models.ImportJob{}).Where("id = ?", jobID).Updates(map[string]interface{}{
			"status": "done", "step": "完成", "message": "导入完成",
			"progress": 100, "result_json": string(data),
			"finished_at": &now, "updated_at": now,
		})
	}

	updateJob("解析文本", "正在解析 AK/SK...", 10)
	parsed := parseAccountText(rawText)
	ak := parsed["access_key_id"]
	sk := parsed["access_key_secret"]
	if ak == "" || sk == "" {
		failJob("无法从文本中提取 AccessKey ID 或 Secret", "auth_failed")
		return
	}

	loginName := parsed["login_name"]
	remark := parsed["remark"]
	accountSlug := slugifyAccount(loginName)
	if accountSlug == "" {
		accountSlug = slugifyAccount(remark)
	}
	if accountSlug == "" && len(ak) >= 6 {
		accountSlug = "account-" + strings.ToLower(ak[len(ak)-6:])
	}

	updateJob("扫描实例", "正在通过 API 扫描实例...", 30)

	regions := []string{parsed["region_id"]}
	if scanAll {
		regions = allAliyunRegions
	}

	type discoveredInst struct {
		InstanceID string `json:"instance_id"`
		Name       string `json:"name"`
		RegionID   string `json:"region_id"`
		Status     string `json:"status"`
		PublicIP   string `json:"public_ip"`
		PrivateIP  string `json:"private_ip"`
	}

	var allDiscovered []discoveredInst

	if !scanAll {
		client := aliyun.NewClient(ak, sk, regions[0])
		instances, err := aliyun.DescribeInstances(client)
		if err != nil {
			failJob(fmt.Sprintf("扫描区域 %s 失败: %v", regions[0], err), "network_error")
			return
		}
		for _, inst := range instances {
			allDiscovered = append(allDiscovered, discoveredInst{
				InstanceID: inst.InstanceID, Name: inst.Name,
				RegionID: inst.RegionID, Status: inst.Status, PublicIP: inst.PublicIP,
			})
		}
	} else {
		const workers = 10
		var (
			mu        sync.Mutex
			wg        sync.WaitGroup
			completed int64
			total     = int64(len(regions))
			sem       = make(chan struct{}, workers)
		)

		go func() {
			for {
				done := atomic.LoadInt64(&completed)
				if done >= total {
					return
				}
				pct := 30 + int(float64(done)/float64(total)*50)
				mu.Lock()
				lastRegion := ""
				if int(done) < len(regions) {
					lastRegion = regions[done]
				}
				mu.Unlock()
				updateJob("扫描实例", fmt.Sprintf("并行扫描区域 (%d/%d) %s...", done, total, lastRegion), pct)
				time.Sleep(300 * time.Millisecond)
			}
		}()

		for _, region := range regions {
			wg.Add(1)
			sem <- struct{}{}
			go func(r string) {
				defer wg.Done()
				defer func() { <-sem }()

				client := aliyun.NewClient(ak, sk, r)
				instances, err := aliyun.DescribeInstances(client)
				if err != nil {
					log.Printf("[import] region %s scan failed: %v", r, err)
					atomic.AddInt64(&completed, 1)
					return
				}

				var batch []discoveredInst
				for _, inst := range instances {
					batch = append(batch, discoveredInst{
						InstanceID: inst.InstanceID, Name: inst.Name,
						RegionID: inst.RegionID, Status: inst.Status, PublicIP: inst.PublicIP,
					})
				}

				mu.Lock()
				allDiscovered = append(allDiscovered, batch...)
				mu.Unlock()
				atomic.AddInt64(&completed, 1)
			}(region)
		}
		wg.Wait()
	}

	updateJob("入库", "正在导入实例数据...", 85)

	imported, updated := 0, 0
	for _, d := range allDiscovered {
		encAK, _ := crypto.Encrypt(ak)
		encSK, _ := crypto.Encrypt(sk)

		var existing models.EcsInstance
		if database.DB.Where("instance_id = ?", d.InstanceID).First(&existing).Error == nil {
			existing.AccessKeyID = encAK
			existing.AccessKeySK = encSK
			existing.IsEncrypted = true
			existing.Status = d.Status
			existing.PublicIP = d.PublicIP
			existing.CredentialStatus = "ok"
			existing.CredentialError = ""
			existing.TrafficStrategy = "life"
			existing.LifeTotalLimit = 500
			existing.AutoStartEnabled = true
			existing.MonitorEnabled = true
			database.DB.Save(&existing)
			updated++
		} else {
			inst := models.EcsInstance{
				Name:              d.Name,
				InstanceID:        d.InstanceID,
				RegionID:          d.RegionID,
				AccessKeyID:       encAK,
				AccessKeySK:       encSK,
				IsEncrypted:       true,
				TrafficStrategy:   "life",
				LifeTotalLimit:    500,
				AlertThresholdPct: 80,
				MonitorEnabled:    true,
				AutoStartEnabled:  true,
				Status:            d.Status,
				PublicIP:          d.PublicIP,
				Tag:               accountSlug,
				LastChecked:       time.Now(),
			}
			if inst.Name == "" {
				inst.Name = d.InstanceID
			}
			database.DB.Create(&inst)
			imported++
		}
	}

	result := map[string]interface{}{
		"account_slug":     accountSlug,
		"discovered_count": len(allDiscovered),
		"imported_count":   imported,
		"updated_count":    updated,
		"instances":        allDiscovered,
	}
	doneJob(result)
}
