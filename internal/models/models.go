package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                  uint           `gorm:"primaryKey" json:"id"`
	Username            string         `gorm:"uniqueIndex;size:150;not null" json:"username"`
	PasswordHash        string         `gorm:"size:256;not null" json:"-"`
	FailedLoginCount    int            `gorm:"default:0" json:"-"`
	LockedUntil         *time.Time     `json:"-"`
	ForcePasswordChange bool           `gorm:"default:false" json:"force_password_change"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
}

type EcsInstance struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"size:150;not null" json:"name"`
	AccessKeyID string `gorm:"size:500;column:access_key_id" json:"-"`
	AccessKeySK string `gorm:"size:500;column:access_key_secret" json:"-"`
	IsEncrypted bool   `gorm:"default:true" json:"-"`
	RegionID    string `gorm:"size:50;not null" json:"region_id"`
	InstanceID  string `gorm:"size:50;not null;uniqueIndex" json:"instance_id"`

	TrafficStrategy    string  `gorm:"size:50;default:cycle" json:"traffic_strategy"`
	MonthlyLimit       float64 `gorm:"default:0" json:"monthly_limit"`
	LifeTotalLimit     float64 `gorm:"default:0" json:"life_total_limit"`
	HourlyPrice        float64 `gorm:"default:0" json:"hourly_price"`
	MonthlyFreeAllow   float64 `gorm:"default:200" json:"monthly_free_allowance"`
	TotalTrafficSum    float64 `gorm:"default:0" json:"total_traffic_sum"`
	CurrentMonthTraffic float64 `gorm:"default:0" json:"current_month_traffic"`
	LastAPITraffic     float64 `gorm:"default:0" json:"last_api_traffic"`
	AlertThresholdPct  int     `gorm:"default:80" json:"alert_threshold_pct"`

	Tag   string `gorm:"size:100;default:''" json:"tag"`
	Notes string `gorm:"type:text;default:''" json:"notes"`

	Status    string `gorm:"size:50;default:Unknown" json:"status"`
	PublicIP  string `gorm:"size:100;default:''" json:"public_ip"`
	PrivateIP string `gorm:"size:100;default:''" json:"private_ip"`
	IPv6Addr  string `gorm:"size:100;default:''" json:"ipv6_addr"`

	CPU          int    `gorm:"default:0" json:"cpu"`
	Memory       int    `gorm:"default:0" json:"memory"`
	OSType       string `gorm:"size:20;default:''" json:"os_type"`
	OSName       string `gorm:"size:200;default:''" json:"os_name"`
	ImageID      string `gorm:"size:200;default:''" json:"image_id"`
	Bandwidth     int    `gorm:"default:0" json:"bandwidth"`
	BandwidthType string `gorm:"size:20;default:''" json:"bandwidth_type"`
	ExpiredTime   string `gorm:"size:50;default:''" json:"expired_time"`
	CreationTime string `gorm:"size:50;default:''" json:"creation_time"`

	AutoStopEnabled  bool `gorm:"default:false" json:"auto_stop_enabled"`
	AutoStartEnabled bool `gorm:"default:false" json:"auto_start_enabled"`
	MonitorEnabled   bool `gorm:"default:true" json:"monitoring_enabled"`

	CredentialStatus       string     `gorm:"size:50;default:ok" json:"credential_status"`
	CredentialError        string     `gorm:"size:500;default:''" json:"credential_error"`
	CredentialLastFailedAt *time.Time `json:"credential_last_failed_at"`

	RealCreationTime *time.Time `json:"real_creation_time"`
	LastChecked      time.Time  `json:"last_checked"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`

	TrafficLogs   []TrafficLog   `gorm:"foreignKey:InstanceID;constraint:OnDelete:CASCADE" json:"-"`
	OperationLogs []OperationLog `gorm:"foreignKey:InstanceID;constraint:OnDelete:CASCADE" json:"-"`
	Schedules     []ScheduleTask `gorm:"foreignKey:InstanceID;constraint:OnDelete:CASCADE" json:"-"`
}

type TrafficLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	InstanceID uint      `gorm:"not null;index" json:"instance_id"`
	TrafficGB  float64   `gorm:"default:0" json:"traffic_gb"`
	Timestamp  time.Time `gorm:"autoCreateTime" json:"timestamp"`
}

type OperationLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	InstanceID *uint     `gorm:"index" json:"instance_id"`
	Action     string    `gorm:"size:50;not null" json:"action"`
	Detail     string    `gorm:"size:500;default:''" json:"detail"`
	Operator   string    `gorm:"size:100;default:system" json:"operator"`
	Timestamp  time.Time `gorm:"autoCreateTime" json:"timestamp"`
}

type AlertConfig struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	NotifyType string `gorm:"size:50;default:telegram" json:"notify_type"`
	WebhookURL string `gorm:"size:500;default:''" json:"webhook_url"`
	TGBotToken string `gorm:"size:200;default:''" json:"tg_bot_token"`
	TGChatID   string `gorm:"size:100;default:''" json:"tg_chat_id"`
	Enabled    bool   `gorm:"default:false" json:"enabled"`
}

type NotificationLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	InstanceName string    `gorm:"size:150;default:''" json:"instance_name"`
	NotifyType   string    `gorm:"size:50;not null" json:"notify_type"`
	Message      string    `gorm:"type:text;not null" json:"message"`
	Success      bool      `gorm:"default:true" json:"success"`
	ErrorMessage string    `gorm:"size:500;default:''" json:"error_message"`
	Attempts     int       `gorm:"default:1" json:"attempts"`
	Timestamp    time.Time `gorm:"autoCreateTime" json:"timestamp"`
}

type ScheduleTask struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	InstanceID uint      `gorm:"not null;index" json:"instance_id"`
	Action     string    `gorm:"size:20;not null" json:"action"` // start, stop
	Hour       int       `gorm:"not null" json:"hour"`
	Minute     int       `gorm:"not null" json:"minute"`
	DaysOfWeek string    `gorm:"size:50;default:*" json:"days_of_week"`
	Enabled    bool      `gorm:"default:true" json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`

	Instance EcsInstance `gorm:"foreignKey:InstanceID" json:"-"`
}

type CloudflareConfig struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	APIToken  string    `gorm:"size:800;default:''" json:"-"`
	ZoneID    string    `gorm:"size:100;default:''" json:"zone_id"`
	Domain    string    `gorm:"size:255;default:''" json:"domain"`
	TesterIP  string    `gorm:"size:100;default:''" json:"tester_ip"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DnsFailover struct {
	ID              uint   `gorm:"primaryKey" json:"id"`
	Domain          string `gorm:"size:255;not null" json:"domain"`
	PrimaryServerID uint   `gorm:"not null" json:"primary_server_id"`
	BackupServerIDs string `gorm:"type:text;default:[]" json:"-"` // JSON array

	CheckPort            int `gorm:"default:80" json:"check_port"`
	CheckIntervalMinutes int `gorm:"default:10" json:"check_interval_minutes"`

	CurrentActiveServerID *uint `json:"current_active_server_id"`
	Enabled               bool  `gorm:"default:true" json:"enabled"`

	LastCheckTime  *time.Time `json:"last_check_time"`
	LastSwitchTime *time.Time `json:"last_switch_time"`
	CreatedAt      time.Time  `json:"created_at"`

	PrimaryServer       EcsInstance      `gorm:"foreignKey:PrimaryServerID" json:"-"`
	CurrentActiveServer *EcsInstance     `gorm:"foreignKey:CurrentActiveServerID" json:"-"`
	Logs                []DnsFailoverLog `gorm:"foreignKey:FailoverID;constraint:OnDelete:CASCADE" json:"-"`
}

func (d *DnsFailover) GetBackupIDs() []uint {
	var ids []uint
	json.Unmarshal([]byte(d.BackupServerIDs), &ids)
	return ids
}

func (d *DnsFailover) SetBackupIDs(ids []uint) {
	data, _ := json.Marshal(ids)
	d.BackupServerIDs = string(data)
}

type DnsFailoverLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	FailoverID   *uint     `gorm:"index" json:"failover_id"`
	Action       string    `gorm:"size:50;default:check" json:"action"`
	Message      string    `gorm:"type:text;default:''" json:"message"`
	FromServerID *uint     `json:"from_server_id"`
	ToServerID   *uint     `json:"to_server_id"`
	CreatedAt    time.Time `json:"created_at"`
}

type ImportJob struct {
	ID         string     `gorm:"primaryKey;size:50" json:"id"`
	Status     string     `gorm:"size:20;default:queued" json:"status"`
	Step       string     `gorm:"size:100;default:''" json:"step"`
	Message    string     `gorm:"size:500;default:''" json:"message"`
	Progress   int        `gorm:"default:0" json:"progress"`
	Error      string     `gorm:"type:text;default:''" json:"error"`
	ResultJSON string     `gorm:"type:text;default:null" json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

func (j *ImportJob) GetResult() any {
	if j.ResultJSON == "" || j.ResultJSON == "null" {
		return nil
	}
	var v any
	json.Unmarshal([]byte(j.ResultJSON), &v)
	return v
}

func (j *ImportJob) SetResult(v any) {
	data, _ := json.Marshal(v)
	j.ResultJSON = string(data)
}

func AllModels() []any {
	return []any{
		&User{},
		&EcsInstance{},
		&TrafficLog{},
		&OperationLog{},
		&AlertConfig{},
		&NotificationLog{},
		&ScheduleTask{},
		&CloudflareConfig{},
		&DnsFailover{},
		&DnsFailoverLog{},
		&ImportJob{},
	}
}
