package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Port              int
	Debug             bool
	SecretKey         string
	EncryptKey        string
	DBPath            string
	DataDir           string
	DataRetentionDays int
	PublicURL         string

	DisableScheduler bool
	Role             string // "all", "web", "scheduler"

	// External
	GoogleDriveFolderID      string
	GoogleServiceAccountFile string
	GitHubSyncRepo           string
	PortCheckerTesterIP      string

	// Tokens
	IPv6ScriptTokenExpires int
}

func Load() *Config {
	baseDir, _ := os.Getwd()
	dataDir := filepath.Join(baseDir, "data")
	os.MkdirAll(dataDir, 0755)

	loadEnvFile(filepath.Join(baseDir, ".env"))

	cfg := &Config{
		Port:              envInt("PANEL_PORT", 5000),
		Debug:             envBool("PANEL_DEBUG", false),
		SecretKey:         envOrGenerate("SECRET_KEY", baseDir, 32),
		DBPath:            envStr("DNS_PANEL_DB_PATH", filepath.Join(dataDir, "panel.db")),
		DataDir:           dataDir,
		DataRetentionDays: envInt("DATA_RETENTION_DAYS", 90),
		PublicURL:         envStr("PUBLIC_PANEL_URL", ""),

		DisableScheduler: envBool("DNS_PANEL_DISABLE_SCHEDULER", false),
		Role:             envStr("DNS_PANEL_ROLE", "all"),

		GoogleDriveFolderID:      envStr("GOOGLE_DRIVE_FOLDER_ID", ""),
		GoogleServiceAccountFile: envStr("GOOGLE_SERVICE_ACCOUNT_FILE", "service_account.json"),
		GitHubSyncRepo:           envStr("GITHUB_SYNC_REPO", ""),
		PortCheckerTesterIP:      envStr("PORT_CHECKER_TESTER_IP", ""),
		IPv6ScriptTokenExpires:   envInt("IPV6_SCRIPT_TOKEN_EXPIRES", 1800),
	}

	cfg.EncryptKey = loadEncryptKey(cfg.DataDir)

	return cfg
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}

func envStr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func envOrGenerate(key, baseDir string, byteLen int) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	b := make([]byte, byteLen)
	rand.Read(b)
	val := hex.EncodeToString(b)
	appendToEnv(filepath.Join(baseDir, ".env"), key, val)
	return val
}

func loadEncryptKey(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("ENCRYPT_KEY")); v != "" {
		return v
	}

	keyFile := filepath.Join(dataDir, "encrypt.key")
	if data, err := os.ReadFile(keyFile); err == nil {
		if k := strings.TrimSpace(string(data)); k != "" {
			return k
		}
	}

	marker := filepath.Join(dataDir, ".encrypt_key_initialized")
	if _, err := os.Stat(marker); err == nil {
		fmt.Println(strings.Repeat("!", 60))
		fmt.Println("CRITICAL: ENCRYPT_KEY 丢失！无法解密已有数据。")
		fmt.Println("请从备份恢复 data/encrypt.key 或在 .env 中设置 ENCRYPT_KEY。")
		fmt.Println(strings.Repeat("!", 60))
	}

	b := make([]byte, 32)
	rand.Read(b)
	key := hex.EncodeToString(b)

	os.WriteFile(keyFile, []byte(key+"\n"), 0600)
	os.WriteFile(marker, []byte("1"), 0644)
	return key
}

func appendToEnv(path, key, val string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n%s=%s\n", key, val)
}
