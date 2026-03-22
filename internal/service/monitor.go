package service

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
)

const anomalyIncreasePct = 20.0

var instanceLocks sync.Map

func acquireInstanceLock(id uint) bool {
	_, loaded := instanceLocks.LoadOrStore(id, true)
	return !loaded
}

func releaseInstanceLock(id uint) {
	instanceLocks.Delete(id)
}

func getAliyunClient(inst *models.EcsInstance) (*aliyun.Client, error) {
	ak, err := crypto.Decrypt(inst.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt AK: %w", err)
	}
	sk, err := crypto.Decrypt(inst.AccessKeySK)
	if err != nil {
		return nil, fmt.Errorf("decrypt SK: %w", err)
	}
	return aliyun.NewClient(ak, sk, inst.RegionID), nil
}

func CheckAndManageInstance(instanceID uint) error {
	if !acquireInstanceLock(instanceID) {
		return nil
	}
	defer releaseInstanceLock(instanceID)

	var inst models.EcsInstance
	if err := database.DB.First(&inst, instanceID).Error; err != nil {
		return err
	}

	if inst.AccessKeyID == "" || inst.AccessKeySK == "" {
		return fmt.Errorf("missing AK/SK for %s", inst.Name)
	}

	log.Printf("[monitor] Checking: %s (%s)...", inst.Name, inst.InstanceID)

	client, err := getAliyunClient(&inst)
	if err != nil {
		return err
	}

	previousAPIGB := inst.LastAPITraffic
	var currentAPIGB float64
	var deltaGB float64

	trafficGB, trafficErr := aliyun.GetTotalTrafficGB(client, inst.RegionID)
	if trafficErr == nil {
		currentAPIGB = trafficGB
		updateCredentialStatus(&inst, "ok", "")
	} else {
		currentAPIGB = previousAPIGB
		if billingErr, ok := trafficErr.(*aliyun.BillingQueryError); ok {
			credStatus := aliyun.CredentialStatusFromBillingError(billingErr)
			if credStatus != "ok" {
				updateCredentialStatus(&inst, credStatus, billingErr.RawError)
			}
		}
		log.Printf("[monitor] traffic query failed for %s: %v", inst.Name, trafficErr)
	}

	if previousAPIGB > 0 && currentAPIGB < previousAPIGB {
		deltaGB = currentAPIGB
	} else {
		deltaGB = math.Max(currentAPIGB-previousAPIGB, 0)
	}

	inst.CurrentMonthTraffic += deltaGB
	inst.LastAPITraffic = currentAPIGB

	if inst.TrafficStrategy == "life" {
		inst.TotalTrafficSum += deltaGB
	} else {
		inst.TotalTrafficSum = inst.CurrentMonthTraffic
	}

	displayUsage := inst.TotalTrafficSum
	if inst.TrafficStrategy != "life" {
		displayUsage = inst.CurrentMonthTraffic
	}

	var lastLog models.TrafficLog
	hasLog := database.DB.Where("instance_id = ?", inst.ID).Order("timestamp desc").First(&lastLog).Error == nil
	if !hasLog || time.Since(lastLog.Timestamp).Seconds() >= 60 {
		database.DB.Create(&models.TrafficLog{InstanceID: inst.ID, TrafficGB: displayUsage})
	}

	if ecsInfo, err := aliyun.GetECSInfo(client, inst.InstanceID); err == nil && ecsInfo != nil {
		inst.Status = ecsInfo.Status
		inst.PublicIP = ecsInfo.PublicIP
		inst.PrivateIP = ecsInfo.PrivateIP
		if ecsInfo.IPv6Addr != "" {
			inst.IPv6Addr = ecsInfo.IPv6Addr
		}
	}

	autoStartStopLogic(client, &inst)
	checkAlerts(&inst, previousAPIGB, currentAPIGB)

	inst.LastChecked = time.Now()
	return database.DB.Save(&inst).Error
}

func autoStartStopLogic(client *aliyun.Client, inst *models.EcsInstance) {
	status := inst.Status
	autoStartEligible := status == "Stopped" || status == "Stopping"

	if inst.AutoStartEnabled && autoStartEligible {
		log.Printf("[monitor] ECS=%s, try auto-start: %s", status, inst.Name)
		if ok, _ := aliyun.ECSStart(client, inst.InstanceID); ok {
			inst.Status = "Starting"
		}
	}

	if !inst.AutoStopEnabled {
		return
	}

	if inst.TrafficStrategy == "cycle" {
		monthlyQuota := inst.MonthlyLimit
		if monthlyQuota > 0 {
			if inst.CurrentMonthTraffic < monthlyQuota {
				if autoStartEligible {
					if ok, _ := aliyun.ECSStart(client, inst.InstanceID); ok {
						inst.Status = "Starting"
					}
				}
			} else if status == "Running" {
				log.Printf("[monitor] traffic exceeded (%.2f >= %.0f), stop %s", inst.CurrentMonthTraffic, monthlyQuota, inst.Name)
				if ok, _ := aliyun.ECSStop(client, inst.InstanceID); ok {
					inst.Status = "Stopping"
				}
			}
		}
	} else if inst.TrafficStrategy == "life" {
		lifeLimit := inst.LifeTotalLimit
		if lifeLimit > 0 && inst.TotalTrafficSum >= lifeLimit && status == "Running" {
			log.Printf("[monitor] LIFE quota exhausted (%.2f >= %.0f), stop %s", inst.TotalTrafficSum, lifeLimit, inst.Name)
			if ok, _ := aliyun.ECSStop(client, inst.InstanceID); ok {
				inst.Status = "Stopping"
			}
		}
	}
}

func checkAlerts(inst *models.EcsInstance, previousAPIGB, currentAPIGB float64) {
	var alertCfg models.AlertConfig
	if err := database.DB.First(&alertCfg).Error; err != nil || !alertCfg.Enabled || alertCfg.WebhookURL == "" {
		return
	}

	var limit, alertTraffic float64
	if inst.TrafficStrategy == "life" {
		limit = inst.LifeTotalLimit
		alertTraffic = inst.TotalTrafficSum
	} else {
		limit = inst.MonthlyLimit
		alertTraffic = inst.CurrentMonthTraffic
	}

	thresholdPct := inst.AlertThresholdPct
	if thresholdPct == 0 {
		thresholdPct = 80
	}

	if limit > 0 {
		usagePct := alertTraffic / limit * 100
		if usagePct >= float64(thresholdPct) {
			if canSendAlert(inst.Name, 3600) {
				msg := fmt.Sprintf("[%s] 流量告警\n已用: %.2f GB / 上限: %.0f GB (%.1f%%)\n状态: %s",
					inst.Name, alertTraffic, limit, usagePct, inst.Status)
				SendAlert(alertCfg.NotifyType, alertCfg.WebhookURL, msg, inst.Name)
			}
		}
	}

	if previousAPIGB > 0 && currentAPIGB > previousAPIGB {
		increasePct := (currentAPIGB - previousAPIGB) / previousAPIGB * 100
		if increasePct >= anomalyIncreasePct {
			if canSendAlert(inst.Name, 1800) {
				msg := fmt.Sprintf("[%s] 流量异常\nAPI读数从 %.2f GB 增至 %.2f GB (+%.1f%%)\n本月累计: %.2f GB\n状态: %s",
					inst.Name, previousAPIGB, currentAPIGB, increasePct, inst.CurrentMonthTraffic, inst.Status)
				SendAlert(alertCfg.NotifyType, alertCfg.WebhookURL, msg, inst.Name)
			}
		}
	}
}

func canSendAlert(instanceName string, cooldownSeconds int) bool {
	var lastNotif models.NotificationLog
	err := database.DB.Where("instance_name = ?", instanceName).Order("timestamp desc").First(&lastNotif).Error
	if err != nil {
		return true
	}
	return time.Since(lastNotif.Timestamp).Seconds() > float64(cooldownSeconds)
}

func updateCredentialStatus(inst *models.EcsInstance, status, errMsg string) {
	inst.CredentialStatus = status
	if status == "ok" {
		inst.CredentialError = ""
		inst.CredentialLastFailedAt = nil
	} else {
		if len(errMsg) > 500 {
			errMsg = errMsg[:500]
		}
		inst.CredentialError = errMsg
		now := time.Now()
		inst.CredentialLastFailedAt = &now
	}
}

func ECSAction(instanceID uint, action string) (bool, string) {
	var inst models.EcsInstance
	if err := database.DB.First(&inst, instanceID).Error; err != nil {
		return false, "instance not found"
	}

	client, err := getAliyunClient(&inst)
	if err != nil {
		return false, err.Error()
	}

	switch action {
	case "start":
		return aliyun.ECSStart(client, inst.InstanceID)
	case "stop":
		return aliyun.ECSStop(client, inst.InstanceID)
	case "release":
		return aliyun.ECSRelease(client, inst.InstanceID)
	default:
		return false, "unknown action: " + action
	}
}
