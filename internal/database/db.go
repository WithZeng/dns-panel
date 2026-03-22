package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/WithZeng/dns-panel/internal/config"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Init(cfg *config.Config) error {
	os.MkdirAll(filepath.Dir(cfg.DBPath), 0755)

	logLevel := logger.Warn
	if cfg.Debug {
		logLevel = logger.Info
	}

	var err error
	DB, err = gorm.Open(sqlite.Open(cfg.DBPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON"), &gorm.Config{
		Logger: logger.New(log.New(os.Stdout, "\n", log.LstdFlags), logger.Config{
			SlowThreshold: 200 * time.Millisecond,
			LogLevel:      logLevel,
			Colorful:      true,
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	sqlDB, _ := DB.DB()
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	if err := DB.AutoMigrate(models.AllModels()...); err != nil {
		return fmt.Errorf("auto-migrate failed: %w", err)
	}

	ensureDefaultAdmin()
	log.Printf("Database ready: %s", cfg.DBPath)
	return nil
}

func ensureDefaultAdmin() {
	var count int64
	DB.Model(&models.User{}).Count(&count)
	if count > 0 {
		log.Printf("Database OK: %d user(s) found.", count)
		return
	}

	password := generatePassword(16)
	hash, _ := hashPassword(password)
	admin := models.User{
		Username:            "admin",
		PasswordHash:        hash,
		ForcePasswordChange: true,
	}
	if err := DB.Create(&admin).Error; err != nil {
		log.Printf("Admin creation skipped: %s", err)
		return
	}

	credPath := filepath.Join(filepath.Dir(os.Getenv("DNS_PANEL_DB_PATH")), "initial_admin_credentials.txt")
	if credPath == filepath.Join("", "initial_admin_credentials.txt") {
		credPath = "data/initial_admin_credentials.txt"
	}
	os.MkdirAll(filepath.Dir(credPath), 0755)
	content := fmt.Sprintf("DNS Panel 初始管理员账号\nusername=admin\npassword=%s\n请登录后立即修改密码。\n", password)
	os.WriteFile(credPath, []byte(content), 0600)
	log.Printf("Default admin created. Password saved to %s", credPath)

	now := time.Now().Format(time.RFC3339)
	marker := filepath.Join(filepath.Dir(credPath), ".db_initialized")
	os.WriteFile(marker, []byte(now), 0644)
}
