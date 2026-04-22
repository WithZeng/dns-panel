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

	if inst.Status == "Released" {
		return nil
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
		lifetimeGB, lifetimeErr := aliyun.GetCDTLifetimeTrafficGB(client, inst.InstanceID, inst.RegionID)
		if lifetimeErr == nil && lifetimeGB > 0 {
			inst.TotalTrafficSum = lifetimeGB
			log.Printf("[monitor] %s life traffic from CDT billing: %.4f GB", inst.Name, lifetimeGB)
		} else {
			inst.TotalTrafficSum += deltaGB
			if lifetimeErr != nil {
				log.Printf("[monitor] %s CDT lifetime query failed, fallback to delta: %v", inst.Name, lifetimeErr)
			}
		}
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
		inst.Bandwidth = ecsInfo.Bandwidth
		inst.BandwidthType = ecsInfo.BandwidthType
	} else if err == nil && ecsInfo == nil {
		inst.Status = "Released"
		updateCredentialStatus(&inst, "released", "实例已释放或不存在 (DescribeInstances returned empty)")
		log.Printf("[monitor] %s (%s) not found in API, marking as Released", inst.Name, inst.InstanceID)
	} else if err != nil {
		updateCredentialStatus(&inst, "error", err.Error())
		log.Printf("[monitor] GetECSInfo failed for %s: %v", inst.Name, err)
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
				SendAlert(msg, inst.Name)
			}
		}
	}

	if previousAPIGB > 0 && currentAPIGB > previousAPIGB {
		increasePct := (currentAPIGB - previousAPIGB) / previousAPIGB * 100
		if increasePct >= anomalyIncreasePct {
			if canSendAlert(inst.Name, 1800) {
				msg := fmt.Sprintf("[%s] 流量异常\nAPI读数从 %.2f GB 增至 %.2f GB (+%.1f%%)\n本月累计: %.2f GB\n状态: %s",
					inst.Name, previousAPIGB, currentAPIGB, increasePct, inst.CurrentMonthTraffic, inst.Status)
				SendAlert(msg, inst.Name)
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

	var ok bool
	var msg string

	switch action {
	case "start":
		ok, msg = aliyun.ECSStart(client, inst.InstanceID)
	case "stop":
		ok, msg = aliyun.ECSStop(client, inst.InstanceID)
	case "reboot":
		ok, msg = aliyun.ECSReboot(client, inst.InstanceID)
	case "release":
		ok, msg = aliyun.ECSRelease(client, inst.InstanceID)
	default:
		return false, "unknown action: " + action
	}

	if ok {
		switch action {
		case "start":
			inst.Status = "Starting"
		case "stop":
			inst.Status = "Stopping"
		case "reboot":
			inst.Status = "Starting"
		case "release":
			inst.Status = "Released"
		}
		database.DB.Save(&inst)

		if action != "release" {
			go func(id uint) {
				time.Sleep(8 * time.Second)
				if err := CheckAndManageInstance(id); err != nil {
					log.Printf("[ecs_action] delayed refresh failed for instance %d: %v", id, err)
				}
			}(instanceID)
		}
	}

	return ok, msg
}
