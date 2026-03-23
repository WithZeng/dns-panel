package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/config"
	cryptoUtil "github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/handler"
	"github.com/WithZeng/dns-panel/internal/middleware"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
)

type multiRenderer struct {
	templates map[string]*template.Template
}

func (r *multiRenderer) Instance(name string, data interface{}) render.Render {
	t, ok := r.templates[name]
	if !ok {
		log.Printf("[WARN] template %q not found, available: %v", name, r.list())
		return render.HTML{Template: template.Must(template.New("").Parse("template not found: " + name)), Data: data}
	}
	return render.HTML{Template: t, Name: "base", Data: data}
}

func (r *multiRenderer) list() []string {
	keys := make([]string, 0, len(r.templates))
	for k := range r.templates {
		keys = append(keys, k)
	}
	return keys
}

func loadTemplates(funcMap template.FuncMap) *multiRenderer {
	r := &multiRenderer{templates: make(map[string]*template.Template)}
	base := "templates/base.html"
	pages, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to glob templates: %v", err)
	}
	for _, page := range pages {
		name := filepath.Base(page)
		if name == "base.html" {
			continue
		}
		t, err := template.New("").Funcs(funcMap).ParseFiles(base, page)
		if err != nil {
			log.Fatalf("Failed to parse template %s: %v", name, err)
		}
		r.templates[name] = t
		log.Printf("Loaded template: %s", name)
	}
	return r
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "reset-password" {
		runResetPassword()
		return
	}

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

	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b float64) float64 {
			v := a - b
			if v < 0 {
				return 0
			}
			return v
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
	}

	r.HTMLRender = loadTemplates(funcMap)
	r.Static("/static", "./static")

	store := cookie.NewStore([]byte(cfg.SecretKey))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   1800,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("session", store))

	// ─── Public routes ──────────────────────────────────────────
	r.GET("/", func(c *gin.Context) { c.Redirect(302, "/dashboard") })
	r.GET("/health", handler.HealthCheck)
	r.GET("/login", handler.LoginPage)
	r.POST("/login", middleware.RateLimit(10, 60*time.Second), handler.LoginPost)
	r.GET("/logout", handler.Logout)

	// Public IPv6 script (token auth)
	r.GET("/public/instance/:id/ipv6_script.sh", handler.PublicIPv6Script)

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

		// Export & backup
		auth.GET("/export_csv", handler.ExportCSV)
		auth.GET("/download_backup", handler.DownloadBackup)
		auth.GET("/download_backup_plaintext", handler.DownloadBackupPlaintext)

		// Discover & import
		auth.GET("/discover", handler.DiscoverPage)
		auth.POST("/discover", handler.DiscoverPost)
		auth.GET("/import_csv", handler.ImportCSVPage)
		auth.POST("/import_csv", handler.ImportCSVPost)
		auth.GET("/import_account_text", handler.ImportAccountTextPage)
		auth.POST("/import_account_text", handler.ImportAccountTextPost)
		auth.GET("/api/account/import_text/status/:job_id", handler.ImportAccountTextStatus)

		// Batch & check all
		auth.POST("/api/batch", handler.BatchAction)
		auth.GET("/api/check_all", handler.CheckAll)
		auth.GET("/api/region_traffic", handler.APIRegionTraffic)
		auth.GET("/api/billing/cdt/three_months", handler.APICDTThreeMonths)
		auth.GET("/api/traffic_forecast/:id", handler.APITrafficForecast)

		// ECS actions
		auth.POST("/api/instance/:id/start", handler.ECSStartAction)
		auth.POST("/api/instance/:id/stop", handler.ECSStopAction)
		auth.POST("/api/instance/:id/reboot", handler.ECSRebootAction)
		auth.POST("/api/instance/:id/release", handler.ECSReleaseAction)
		auth.POST("/api/instance/:id/refresh", handler.ECSRefreshStatus)
		auth.GET("/api/instance/:id/billing", handler.ECSTrafficBilling)
		auth.POST("/api/instance/:id/check", handler.ForceCheckInstance)
		auth.GET("/api/instance/:id/vnc", handler.ECSVncUrl)
		auth.POST("/api/instance/:id/password", handler.ECSModifyPasswordAction)
		auth.GET("/api/instance/:id/images", handler.ECSImagesAction)
		auth.POST("/api/instance/:id/reset_system", handler.ECSResetSystemAction)
		auth.POST("/api/instance/:id/rename", handler.ECSRenameAction)

		// IPv6
		auth.POST("/api/instance/:id/enable_ipv6", handler.EnableIPv6)
		auth.GET("/api/instance/:id/ipv6_status", handler.GetIPv6Status)
		auth.GET("/instance/:id/ipv6_script.sh", handler.DownloadIPv6Script)

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

		// Version & update
		auth.GET("/api/version", handler.VersionInfo)
		auth.GET("/api/check_update", handler.CheckUpdate)

		// DB Restore
		auth.GET("/restore_db", handler.RestoreDBPage)
		auth.POST("/restore_db", handler.RestoreDBPost)

		// Unified restore page
		auth.GET("/restore", handler.RestorePage)

		// API
		auth.GET("/api/instances", handler.APIInstances)
		auth.POST("/api/instance/:id/notes", handler.UpdateNotes)
		auth.GET("/api/traffic_history/:id", handler.APITrafficHistory)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	log.Printf("ECS Monitor (Go) starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func runResetPassword() {
	cfg := config.Load()
	if err := database.Init(cfg); err != nil {
		log.Fatalf("Database init failed: %v", err)
	}

	newPass := "admin123"
	if len(os.Args) >= 3 {
		newPass = os.Args[2]
	}

	hash, err := database.HashPassword(newPass)
	if err != nil {
		log.Fatalf("Hash failed: %v", err)
	}

	result := database.DB.Model(&models.User{}).Where("username = ?", "admin").Updates(map[string]interface{}{
		"password_hash":     hash,
		"failed_login_count": 0,
		"locked_until":       nil,
	})
	if result.RowsAffected == 0 {
		hash2, _ := database.HashPassword(newPass)
		database.DB.Create(&models.User{Username: "admin", PasswordHash: hash2})
		fmt.Println("Admin user created.")
	}

	fmt.Printf("Password reset OK. Login: admin / %s\n", newPass)
}
