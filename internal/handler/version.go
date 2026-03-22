package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	CurrentVersion = "0.4.0"
	GitHubRepo     = "WithZeng/dns-panel"
	GitHubURL      = "https://github.com/" + GitHubRepo
)

func VersionInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":    CurrentVersion,
		"github_url": GitHubURL,
		"repo":       GitHubRepo,
	})
}

func CheckUpdate(c *gin.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "ECS-Monitor/"+CurrentVersion)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":         true,
			"current_version": CurrentVersion,
			"has_update":      false,
			"message":         "无法连接 GitHub，请稍后再试",
		})
		return
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil || release.TagName == "" {
		c.JSON(http.StatusOK, gin.H{
			"success":         true,
			"current_version": CurrentVersion,
			"has_update":      false,
			"message":         "暂无发布版本",
		})
		return
	}

	latestVersion := release.TagName
	if len(latestVersion) > 0 && latestVersion[0] == 'v' {
		latestVersion = latestVersion[1:]
	}

	hasUpdate := latestVersion != CurrentVersion
	message := "已是最新版本"
	if hasUpdate {
		message = fmt.Sprintf("发现新版本 %s", release.TagName)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"current_version":  CurrentVersion,
		"latest_version":   release.TagName,
		"has_update":       hasUpdate,
		"release_url":      release.HTMLURL,
		"release_notes":    release.Body,
		"message":          message,
	})
}
