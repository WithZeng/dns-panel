package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

func ECSStartAction(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	ok, msg := service.ECSAction(uint(id), "start")
	c.JSON(http.StatusOK, gin.H{"success": ok, "message": msg})
}

func ECSStopAction(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	ok, msg := service.ECSAction(uint(id), "stop")
	c.JSON(http.StatusOK, gin.H{"success": ok, "message": msg})
}

func ECSReleaseAction(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	ok, msg := service.ECSAction(uint(id), "release")
	c.JSON(http.StatusOK, gin.H{"success": ok, "message": msg})
}

func ECSRefreshStatus(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}

	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	info, err := aliyun.GetECSInfo(client, inst.InstanceID)
	if err != nil || info == nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "获取状态失败"})
		return
	}

	inst.Status = info.Status
	inst.PublicIP = info.PublicIP
	inst.PrivateIP = info.PrivateIP
	if info.IPv6Addr != "" {
		inst.IPv6Addr = info.IPv6Addr
	}
	database.DB.Save(&inst)

	c.JSON(http.StatusOK, gin.H{"success": true, "instance": inst})
}

func ECSTrafficBilling(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "实例不存在"})
		return
	}

	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": fmt.Sprintf("凭据解密失败：%s", err.Error())})
		return
	}

	billing, err := aliyun.GetCDTThreeMonthBilling(client, inst.InstanceID, inst.RegionID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	months := make([]gin.H, 0)
	if billing.Months != nil {
		for _, m := range billing.Months {
			months = append(months, gin.H{
				"month":        m.Month,
				"traffic":      m.Traffic,
				"amount":       m.Amount,
				"traffic_unit": m.TrafficUnit,
				"currency":     m.Currency,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"months":        months,
		"total_traffic": billing.TotalTraffic,
		"total_amount":  billing.TotalAmount,
		"currency":      billing.Currency,
		"scope":         billing.Scope,
	})
}

func SecurityGroupsPage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.HTML(http.StatusOK, "security_groups.html", gin.H{
			"instance": inst,
			"error":    err.Error(),
			"username": c.GetString("username"),
		})
		return
	}

	sgIDs, err := aliyun.GetSecurityGroups(client, inst.InstanceID)
	if err != nil {
		c.HTML(http.StatusOK, "security_groups.html", gin.H{
			"instance": inst,
			"error":    err.Error(),
			"username": c.GetString("username"),
		})
		return
	}

	type sgWithRules struct {
		ID    string
		Rules []aliyun.SGRule
	}
	var groups []sgWithRules
	for _, sgID := range sgIDs {
		rules, _ := aliyun.DescribeSGRules(client, sgID)
		groups = append(groups, sgWithRules{ID: sgID, Rules: rules})
	}

	c.HTML(http.StatusOK, "security_groups.html", gin.H{
		"instance": inst,
		"groups":   groups,
		"username": c.GetString("username"),
	})
}

func APISecurityGroupAdd(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}

	var body struct {
		SGID       string `json:"sg_id"`
		Protocol   string `json:"protocol"`
		PortRange  string `json:"port_range"`
		SourceCIDR string `json:"source_cidr"`
		Policy     string `json:"policy"`
		Desc       string `json:"description"`
	}
	c.BindJSON(&body)

	if body.Policy == "" {
		body.Policy = "accept"
	}
	if body.SourceCIDR == "" {
		body.SourceCIDR = "0.0.0.0/0"
	}

	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	ok, msg := aliyun.AuthorizeSG(client, body.SGID, body.Protocol, body.PortRange, body.SourceCIDR, body.Policy, body.Desc)
	logOperation("sg_add", fmt.Sprintf("安全组 %s 添加规则 %s %s", body.SGID, body.Protocol, body.PortRange), &inst.ID, c)
	c.JSON(http.StatusOK, gin.H{"success": ok, "message": msg})
}

func APISecurityGroupRevoke(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}

	var body struct {
		SGID       string `json:"sg_id"`
		Protocol   string `json:"protocol"`
		PortRange  string `json:"port_range"`
		SourceCIDR string `json:"source_cidr"`
		Policy     string `json:"policy"`
	}
	c.BindJSON(&body)

	if body.Policy == "" {
		body.Policy = "accept"
	}
	if body.SourceCIDR == "" {
		body.SourceCIDR = "0.0.0.0/0"
	}

	client, err := getClientFromInstance(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	ok, msg := aliyun.RevokeSG(client, body.SGID, body.Protocol, body.PortRange, body.SourceCIDR, body.Policy)
	logOperation("sg_revoke", fmt.Sprintf("安全组 %s 删除规则 %s %s", body.SGID, body.Protocol, body.PortRange), &inst.ID, c)
	c.JSON(http.StatusOK, gin.H{"success": ok, "message": msg})
}

func ForceCheckInstance(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	go service.CheckAndManageInstance(uint(id))
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "已触发检测"})
}

func getClientFromInstance(inst *models.EcsInstance) (*aliyun.Client, error) {
	if inst.AccessKeyID == "" || inst.AccessKeySK == "" {
		return nil, fmt.Errorf("missing AK/SK")
	}
	ak, err := decryptField(inst.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt AK: %w", err)
	}
	sk, err := decryptField(inst.AccessKeySK)
	if err != nil {
		return nil, fmt.Errorf("decrypt SK: %w", err)
	}
	return aliyun.NewClient(ak, sk, inst.RegionID), nil
}

func decryptField(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !strings.Contains(ciphertext, ":") && len(ciphertext) < 40 {
		return ciphertext, nil
	}
	return crypto.Decrypt(ciphertext)
}
