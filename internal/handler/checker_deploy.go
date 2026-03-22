package handler

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func CheckerDeployPage(c *gin.Context) {
	panelURL := os.Getenv("PUBLIC_PANEL_URL")
	if panelURL == "" {
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		panelURL = fmt.Sprintf("%s://%s", scheme, c.Request.Host)
	}
	panelURL = strings.TrimRight(panelURL, "/")

	installCmdCN := fmt.Sprintf(
		"curl -fsSL %s/agent/install_checker_cn.sh -o /tmp/install_checker_cn.sh && PANEL_BASE_URL=%s bash /tmp/install_checker_cn.sh",
		panelURL, panelURL,
	)
	installCmdGlobal := fmt.Sprintf(
		"curl -fsSL %s/agent/install_checker_global.sh -o /tmp/install_checker_global.sh && PANEL_BASE_URL=%s bash /tmp/install_checker_global.sh",
		panelURL, panelURL,
	)
	installCmdLegacy := fmt.Sprintf(
		"curl -fsSL %s/agent/install_checker.sh -o /tmp/install_checker.sh && PANEL_BASE_URL=%s bash /tmp/install_checker.sh",
		panelURL, panelURL,
	)
	verifyCmd := "curl -s 'http://127.0.0.1:8888/ping?host=1.1.1.1'"

	c.HTML(http.StatusOK, "checker_deploy.html", gin.H{
		"username":           c.GetString("username"),
		"panel_url":          panelURL,
		"install_cmd_cn":     installCmdCN,
		"install_cmd_global": installCmdGlobal,
		"install_cmd_legacy": installCmdLegacy,
		"verify_cmd":         verifyCmd,
	})
}
