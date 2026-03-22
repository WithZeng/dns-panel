package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func ProbeServersPage(c *gin.Context) {
	var probes []models.ProbeServer
	database.DB.Order("name").Find(&probes)
	c.HTML(http.StatusOK, "probe_servers.html", gin.H{
		"probes":   probes,
		"username": c.GetString("username"),
	})
}

func APIProbeServers(c *gin.Context) {
	var probes []models.ProbeServer
	database.DB.Order("name").Find(&probes)
	c.JSON(http.StatusOK, gin.H{"success": true, "servers": probes})
}

func APIProbeServerCreate(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("name"))
	if name == "" {
		var body struct{ Name string `json:"name"` }
		c.BindJSON(&body)
		name = strings.TrimSpace(body.Name)
	}
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "名称不能为空"})
		return
	}

	token := generateToken(32)
	probe := models.ProbeServer{
		Name:       name,
		Token:      token,
		ServerType: "generic",
	}
	database.DB.Create(&probe)
	c.JSON(http.StatusOK, gin.H{"success": true, "server": probe, "token": token})
}

func APIProbeServerGet(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var probe models.ProbeServer
	if err := database.DB.First(&probe, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "server": probe})
}

func APIProbeServerUpdate(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var probe models.ProbeServer
	if err := database.DB.First(&probe, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}
	var body struct {
		Name           string `json:"name"`
		Tag            string `json:"tag"`
		Notes          string `json:"notes"`
		EcsInstanceID  *uint  `json:"ecs_instance_id"`
	}
	c.BindJSON(&body)
	if body.Name != "" {
		probe.Name = body.Name
	}
	probe.Tag = body.Tag
	probe.Notes = body.Notes
	probe.EcsInstanceID = body.EcsInstanceID
	database.DB.Save(&probe)
	c.JSON(http.StatusOK, gin.H{"success": true, "server": probe})
}

func APIProbeServerDelete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	database.DB.Delete(&models.ProbeServer{}, id)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func APIProbeServerResetToken(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var probe models.ProbeServer
	if err := database.DB.First(&probe, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}
	probe.Token = generateToken(32)
	database.DB.Save(&probe)
	c.JSON(http.StatusOK, gin.H{"success": true, "token": probe.Token})
}

func APIProbeReport(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		token = c.Query("token")
	}

	var probe models.ProbeServer
	if err := database.DB.Where("token = ?", token).First(&probe).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "invalid token"})
		return
	}

	var report map[string]any
	if err := c.BindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid body"})
		return
	}

	now := time.Now()
	probe.IsOnline = true
	probe.LastSeen = &now

	if ipv4, ok := report["ipv4"].(string); ok {
		probe.IPv4 = ipv4
	}
	if ipv6, ok := report["ipv6"].(string); ok {
		probe.IPv6 = ipv6
	}
	if cpuName, ok := report["cpu_name"].(string); ok {
		probe.CPUName = cpuName
	}
	if cores, ok := report["cpu_cores"].(float64); ok {
		probe.CPUCores = int(cores)
	}
	if arch, ok := report["arch"].(string); ok {
		probe.Arch = arch
	}
	if osInfo, ok := report["os"].(string); ok {
		probe.OSInfo = osInfo
	}
	if virt, ok := report["virtualization"].(string); ok {
		probe.Virtualization = virt
	}
	if mem, ok := report["mem_total"].(float64); ok {
		probe.MemTotal = int64(mem)
	}
	if swap, ok := report["swap_total"].(float64); ok {
		probe.SwapTotal = int64(swap)
	}
	if disk, ok := report["disk_total"].(float64); ok {
		probe.DiskTotal = int64(disk)
	}

	probe.SetLatestReport(report)
	database.DB.Save(&probe)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func ProbeServerDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var probe models.ProbeServer
	if err := database.DB.First(&probe, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/probe/servers")
		return
	}
	c.HTML(http.StatusOK, "probe_server_detail.html", gin.H{
		"probe":    probe,
		"report":   probe.GetLatestReport(),
		"username": c.GetString("username"),
	})
}

func generateToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}
