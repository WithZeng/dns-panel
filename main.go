package main

import (
	"fmt"
	"html/template"
	"log"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/config"
	cryptoUtil "github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/handler"
	"github.com/WithZeng/dns-panel/internal/middleware"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	if err := cryptoUtil.Init(cfg.EncryptKey); err != nil {
		log.Fatalf("Failed to init encryption: %v", err)
	}
	if err := database.Init(cfg); err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	if !cfg.DisableScheduler && (cfg.Role == "all" || cfg.Role == "scheduler") {
		service.StartScheduler()
		defer service.StopScheduler()
	}

	if cfg.Role == "scheduler" {
		log.Println("Running in scheduler-only mode. Waiting...")
		select {}
	}

	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestLogger())

	r.SetFuncMap(template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b float64) float64 {
			r := a - b
			if r < 0 {
				return 0
			}
			return r
		},
		"mul": func(a, b float64) float64 { return a * b },
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"min": func(a, b float64) float64 {
			if a < b {
				return a
			}
			return b
		},
		"lower":    strings.ToLower,
		"contains": strings.Contains,
		"now":      func() time.Time { return time.Now() },
	})

	store := cookie.NewStore([]byte(cfg.SecretKey))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   1800,
		HttpOnly: true,
		SameSite: 2,
	})
	r.Use(sessions.Sessions("session", store))

	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// ─── Public routes ──────────────────────────────────────────
	r.GET("/", func(c *gin.Context) { c.Redirect(302, "/dashboard") })
	r.GET("/health", handler.HealthCheck)
	r.GET("/login", handler.LoginPage)
	r.POST("/login", middleware.RateLimit(10, 60*time.Second), handler.LoginPost)
	r.GET("/logout", handler.Logout)

	// Probe agent (token auth, no session)
	r.POST("/api/probe/report", handler.APIProbeReport)
	r.GET("/api/probe/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.GET("/ws/agent", handler.WSAgent)

	// ─── Authenticated routes ───────────────────────────────────
	auth := r.Group("/")
	auth.Use(middleware.AuthRequired())
	auth.Use(middleware.ForcePasswordChange())
	{
		auth.GET("/dashboard", handler.Dashboard)
		auth.GET("/change_password", handler.ChangePasswordPage)
		auth.POST("/change_password", handler.ChangePasswordPost)

		// Instance CRUD
		auth.GET("/instance/add", handler.AddInstancePage)
		auth.POST("/instance/add", handler.AddInstancePost)
		auth.GET("/instance/edit/:id", handler.EditInstancePage)
		auth.POST("/instance/edit/:id", handler.EditInstancePost)
		auth.GET("/instance/:id", handler.InstanceDetail)
		auth.POST("/instance/delete/:id", handler.DeleteInstance)

		// Schedules
		auth.GET("/instance/:id/schedules", handler.SchedulesPage)
		auth.POST("/instance/:id/schedules", handler.ScheduleCreate)
		auth.POST("/schedule/:id/toggle", handler.ScheduleToggle)
		auth.POST("/schedule/:id/delete", handler.ScheduleDelete)

		// Logs
		auth.GET("/logs", handler.OperationLogs)
		auth.GET("/notification_logs", handler.NotificationLogs)

		// Alert config
		auth.GET("/alert_config", handler.AlertConfigPage)
		auth.POST("/alert_config", handler.AlertConfigPost)
		auth.POST("/api/test_notification", handler.TestNotification)

		// Export
		auth.GET("/export_csv", handler.ExportCSV)

		// Probe servers
		auth.GET("/probe/servers", handler.ProbeServersPage)
		auth.GET("/probe/server/:id", handler.ProbeServerDetail)

		// ECS actions
		auth.POST("/api/instance/:id/start", handler.ECSStartAction)
		auth.POST("/api/instance/:id/stop", handler.ECSStopAction)
		auth.POST("/api/instance/:id/release", handler.ECSReleaseAction)
		auth.POST("/api/instance/:id/refresh", handler.ECSRefreshStatus)
		auth.GET("/api/instance/:id/billing", handler.ECSTrafficBilling)
		auth.POST("/api/instance/:id/check", handler.ForceCheckInstance)

		// Security groups
		auth.GET("/instance/:id/security_groups", handler.SecurityGroupsPage)
		auth.POST("/api/instance/:id/sg/add", handler.APISecurityGroupAdd)
		auth.POST("/api/instance/:id/sg/revoke", handler.APISecurityGroupRevoke)

		// DNS Failover
		auth.GET("/dns_failover", handler.DNSFailoverPage)
		auth.POST("/dns_failover/cf_config", handler.SaveCloudflareConfig)
		auth.POST("/dns_failover/rules", handler.CreateDNSFailoverRule)
		auth.POST("/dns_failover/rules/:id/toggle", handler.ToggleDNSFailoverRule)
		auth.POST("/dns_failover/rules/:id/delete", handler.DeleteDNSFailoverRule)
		auth.GET("/api/dns_failover/logs", handler.APIDNSFailoverLogs)
		auth.POST("/api/dns_failover/:id/test", handler.APIDNSFailoverTestSwitch)

		// API
		auth.GET("/api/instances", handler.APIInstances)
		auth.POST("/api/instance/:id/notes", handler.UpdateNotes)
		auth.GET("/api/traffic_history/:id", handler.APITrafficHistory)
		auth.GET("/api/probe/servers", handler.APIProbeServers)
		auth.POST("/api/probe/servers", handler.APIProbeServerCreate)
		auth.GET("/api/probe/servers/:id", handler.APIProbeServerGet)
		auth.POST("/api/probe/servers/:id", handler.APIProbeServerUpdate)
		auth.DELETE("/api/probe/servers/:id", handler.APIProbeServerDelete)
		auth.POST("/api/probe/servers/:id/reset-token", handler.APIProbeServerResetToken)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	log.Printf("DNS Panel (Go) starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
