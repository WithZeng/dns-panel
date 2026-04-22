package service

import (
	"fmt"
	"log"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/robfig/cron/v3"
)

var Cron *cron.Cron

func StartScheduler() {
	Cron = cron.New(cron.WithSeconds())

	Cron.AddFunc("0 */3 * * * *", func() {
		log.Println("[scheduler] check_all_instances")
		CheckAllInstances()
	})

	Cron.AddFunc("0 0 0 1 * *", func() {
		log.Println("[scheduler] monthly_traffic_reset")
		MonthlyTrafficReset()
	})

	Cron.AddFunc("0 0 9 * * *", func() {
		log.Println("[scheduler] daily_report")
		DailyReport()
	})

	Cron.AddFunc("0 0 3 * * *", func() {
		log.Println("[scheduler] data_retention_cleanup")
		DataRetentionCleanup(90)
	})

	Cron.AddFunc("0 0 2 * * *", func() {
		log.Println("[scheduler] auto_backup_db")
		// TODO: implement DB backup
	})

	Cron.AddFunc("0 * * * * *", func() {
		RunScheduledTasks()
	})

	Cron.AddFunc("0 */10 * * * *", func() {
		// TODO: DNS failover check
	})

	Cron.Start()
	log.Println("Scheduler started with 7 jobs.")
}

func StopScheduler() {
	if Cron != nil {
		Cron.Stop()
	}
}

func CheckAllInstances() {
	var instances []models.EcsInstance
	database.DB.Where("monitor_enabled = ?", true).Find(&instances)
	for _, inst := range instances {
		if err := CheckAndManageInstance(inst.ID); err != nil {
			log.Printf("[monitor] error checking %s: %v", inst.Name, err)
		}
	}
}


func MonthlyTrafficReset() {
	result := database.DB.Model(&models.EcsInstance{}).Update("current_month_traffic", 0)
	log.Printf("Monthly traffic reset: %d instances updated.", result.RowsAffected)
}

func DailyReport() {
	var alertCfg models.AlertConfig
	if err := database.DB.First(&alertCfg).Error; err != nil || !alertCfg.Enabled {
		return
	}

	var instances []models.EcsInstance
	database.DB.Find(&instances)
	if len(instances) == 0 {
		return
	}

	var online int
	var totalTraffic float64
	for _, inst := range instances {
		if inst.Status == "Running" || inst.Status == "Starting" {
			online++
		}
		totalTraffic += inst.CurrentMonthTraffic
	}

	now := time.Now().Format("2006-01-02")
	msg := fmt.Sprintf("每日流量报告 (%s)\n实例总数: %d | 在线: %d\n本月总流量: %.2f GB\n",
		now, len(instances), online, totalTraffic)
	msg += "--------------------\n"

	for _, inst := range instances {
		var limit, used float64
		if inst.TrafficStrategy == "life" {
			limit = inst.LifeTotalLimit
			used = inst.TotalTrafficSum
		} else {
			limit = inst.MonthlyLimit
			used = inst.CurrentMonthTraffic
		}
		pct := float64(0)
		if limit > 0 {
			pct = used / limit * 100
		}
		emoji := "🔴"
		if inst.Status == "Running" || inst.Status == "Starting" {
			emoji = "🟢"
		}
		msg += fmt.Sprintf("%s %s: %.2f/%.0f GB (%.0f%%)\n", emoji, inst.Name, used, limit, pct)
	}

	SendAlert(msg, "daily_report")
}

func DataRetentionCleanup(days int) {
	cutoff := time.Now().AddDate(0, 0, -days)
	r1 := database.DB.Where("timestamp < ?", cutoff).Delete(&models.TrafficLog{})
	r2 := database.DB.Where("timestamp < ?", cutoff).Delete(&models.NotificationLog{})
	log.Printf("Data retention cleanup: removed %d traffic logs, %d notification logs older than %d days.",
		r1.RowsAffected, r2.RowsAffected, days)
}

func RunScheduledTasks() {
	now := time.Now()
	hour := now.Hour()
	minute := now.Minute()
	dow := int(now.Weekday())
	if dow == 0 {
		dow = 7
	}

	var tasks []models.ScheduleTask
	database.DB.Preload("Instance").Where("enabled = ? AND hour = ? AND minute = ?", true, hour, minute).Find(&tasks)

	for _, task := range tasks {
		if task.DaysOfWeek != "*" {
			// TODO: parse days_of_week and check
		}
		log.Printf("[schedule] Would execute %s on %s", task.Action, task.Instance.Name)
		// TODO: implement start/stop via Aliyun SDK
	}
}
