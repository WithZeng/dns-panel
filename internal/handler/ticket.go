package handler

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func TicketPendingCount(c *gin.Context) {
	role := c.GetString("role")
	var count int64
	q := database.DB.Model(&models.Ticket{}).Where("status = ?", "pending")
	if role != "admin" {
		userID, _ := c.Get("user_id")
		q = q.Where("user_id = ?", userID)
	}
	q.Count(&count)
	c.JSON(http.StatusOK, gin.H{"count": count})
}

func TicketListPage(c *gin.Context) {
	role := c.GetString("role")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	perPage := 20

	q := database.DB.Model(&models.Ticket{})
	if role != "admin" {
		userID, _ := c.Get("user_id")
		q = q.Where("user_id = ?", userID)
	}

	statusFilter := c.Query("status")
	if statusFilter != "" {
		q = q.Where("status = ?", statusFilter)
	}

	var total int64
	q.Count(&total)

	var tickets []models.Ticket
	q.Preload("User").Order("created_at DESC").Offset((page - 1) * perPage).Limit(perPage).Find(&tickets)

	totalPages := int(math.Ceil(float64(total) / float64(perPage)))

	var pendingCount int64
	pq := database.DB.Model(&models.Ticket{}).Where("status = ?", "pending")
	if role != "admin" {
		userID, _ := c.Get("user_id")
		pq = pq.Where("user_id = ?", userID)
	}
	pq.Count(&pendingCount)

	c.HTML(http.StatusOK, "tickets.html", gin.H{
		"tickets":      tickets,
		"page":         page,
		"totalPages":   totalPages,
		"total":        total,
		"pendingCount": pendingCount,
		"statusFilter": statusFilter,
		"username":     c.GetString("username"),
		"role":         role,
	})
}

func TicketCreatePage(c *gin.Context) {
	ticketType := c.DefaultQuery("type", "quota_request")
	c.HTML(http.StatusOK, "ticket_create.html", gin.H{
		"ticketType": ticketType,
		"username":   c.GetString("username"),
		"role":       c.GetString("role"),
	})
}

func TicketCreatePost(c *gin.Context) {
	userID, _ := c.Get("user_id")
	ticketType := c.PostForm("type")
	remark := strings.TrimSpace(c.PostForm("remark"))

	if ticketType != "quota_request" && ticketType != "reset_system" {
		c.HTML(http.StatusBadRequest, "ticket_create.html", gin.H{
			"error":    "无效的工单类型",
			"username": c.GetString("username"),
			"role":     c.GetString("role"),
		})
		return
	}

	ticket := models.Ticket{
		UserID: userID.(uint),
		Type:   ticketType,
		Status: "pending",
		Remark: remark,
	}

	if ticketType == "quota_request" {
		ticket.Subject = "请求配额"
		ticket.AlipayCode = strings.TrimSpace(c.PostForm("alipay_code"))
		ticket.Region = strings.TrimSpace(c.PostForm("region"))
		ticket.Quantity, _ = strconv.Atoi(c.PostForm("quantity"))

		if ticket.AlipayCode == "" {
			c.HTML(http.StatusOK, "ticket_create.html", gin.H{
				"error":      "请输入支付宝口令红包",
				"ticketType": ticketType,
				"username":   c.GetString("username"),
				"role":       c.GetString("role"),
			})
			return
		}
		if ticket.Quantity < 1 {
			ticket.Quantity = 1
		}
	} else if ticketType == "reset_system" {
		ticket.Subject = "请求重置系统权限"
		noDDStr := c.PostForm("no_dd_guarantee")
		if noDDStr != "1" {
			c.HTML(http.StatusOK, "ticket_create.html", gin.H{
				"error":      "请勾选确认未使用 DD 系统的保证",
				"ticketType": ticketType,
				"username":   c.GetString("username"),
				"role":       c.GetString("role"),
			})
			return
		}
		ticket.NoDDGuarantee = true
	}

	database.DB.Create(&ticket)
	logOperation("create_ticket", fmt.Sprintf("创建工单 #%d: %s", ticket.ID, ticket.Subject), nil, c)
	c.Redirect(http.StatusFound, fmt.Sprintf("/ticket/%d", ticket.ID))
}

func TicketDetailPage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	role := c.GetString("role")

	var ticket models.Ticket
	if err := database.DB.Preload("User").First(&ticket, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/tickets")
		return
	}

	if role != "admin" {
		userID, _ := c.Get("user_id")
		if ticket.UserID != userID.(uint) {
			c.Redirect(http.StatusFound, "/tickets")
			return
		}
	}

	var regionStats []gin.H
	var groupOptions []gin.H
	var totalUnassigned int64
	var allUnassigned []models.EcsInstance
	requestedRegionName := ""
	requestedRegionID := ""
	if role == "admin" && ticket.Type == "quota_request" && (ticket.Status == "approved" || ticket.Status == "pending") {
		subQ := database.DB.Model(&models.UserInstance{}).Select("instance_id")

		database.DB.Where("id NOT IN (?)", subQ).Order("region_id, group_name, name").Find(&allUnassigned)
		totalUnassigned = int64(len(allUnassigned))

		regionCount := make(map[string]int)
		for _, inst := range allUnassigned {
			regionCount[inst.RegionID]++
		}
		for rid, cnt := range regionCount {
			name := regionGroupName(rid)
			dotColor := "bg-gray-300 dark:bg-gray-600"
			if cnt > 5 {
				dotColor = "bg-emerald-500"
			} else if cnt > 0 {
				dotColor = "bg-amber-500"
			}
			regionStats = append(regionStats, gin.H{"RegionID": rid, "Name": name, "Count": cnt, "DotColor": dotColor})
		}

		if ticket.Region != "" && ticket.Region != "不限" {
			requestedRegionName = ticket.Region
			for rid, rname := range regionNameMap {
				if rname == ticket.Region {
					requestedRegionName = rname
					requestedRegionID = rid
					break
				}
			}
		}

		groupCount := make(map[string]int)
		for _, inst := range allUnassigned {
			gn := inst.GroupName
			if gn == "" {
				gn = "未分组"
			}
			groupCount[gn]++
		}
		for gn, cnt := range groupCount {
			groupOptions = append(groupOptions, gin.H{"GroupName": gn, "Count": cnt})
		}
	}

	c.HTML(http.StatusOK, "ticket_detail.html", gin.H{
		"ticket":              ticket,
		"regionStats":         regionStats,
		"groupOptions":        groupOptions,
		"totalUnassigned":     int(totalUnassigned),
		"allUnassigned":       allUnassigned,
		"requestedRegionName": requestedRegionName,
		"requestedRegionID":   requestedRegionID,
		"username":            c.GetString("username"),
		"role":                role,
	})
}

func TicketReviewPost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	action := c.PostForm("action")
	adminReply := strings.TrimSpace(c.PostForm("admin_reply"))

	var ticket models.Ticket
	if err := database.DB.First(&ticket, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/tickets")
		return
	}

	if ticket.Status != "pending" {
		c.Redirect(http.StatusFound, fmt.Sprintf("/ticket/%d", ticket.ID))
		return
	}

	now := time.Now()
	reviewer := c.GetString("username")

	if action == "approve" {
		ticket.Status = "approved"
	} else if action == "reject" {
		ticket.Status = "rejected"
	} else {
		c.Redirect(http.StatusFound, fmt.Sprintf("/ticket/%d", ticket.ID))
		return
	}

	ticket.AdminReply = adminReply
	ticket.ReviewedBy = reviewer
	ticket.ReviewedAt = &now
	database.DB.Save(&ticket)

	logOperation("review_ticket", fmt.Sprintf("审核工单 #%d: %s → %s", ticket.ID, ticket.Subject, ticket.Status), nil, c)
	c.Redirect(http.StatusFound, fmt.Sprintf("/ticket/%d", ticket.ID))
}

func TicketAssignQuotaPost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var ticket models.Ticket
	if err := database.DB.Preload("User").First(&ticket, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "工单不存在"})
		return
	}

	if ticket.Type != "quota_request" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "工单类型不支持分配"})
		return
	}
	if ticket.Status == "completed" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "工单已完成分配，不可重复操作"})
		return
	}
	if ticket.Status != "approved" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "工单状态不允许分配"})
		return
	}

	subQ := database.DB.Model(&models.UserInstance{}).Select("instance_id")

	c.Request.ParseForm()
	manualIDs := c.PostFormArray("instance_ids")

	var toAssign []models.EcsInstance

	if len(manualIDs) > 0 {
		var ids []uint
		for _, s := range manualIDs {
			if v, err := strconv.Atoi(s); err == nil {
				ids = append(ids, uint(v))
			}
		}
		if len(ids) > 0 {
			database.DB.Where("id IN ? AND id NOT IN (?)", ids, subQ).Find(&toAssign)
		}
	} else {
		groupFilter := strings.TrimSpace(c.PostForm("group"))
		quantity, _ := strconv.Atoi(c.PostForm("quantity"))
		if quantity < 1 {
			quantity = ticket.Quantity
		}
		if quantity < 1 {
			quantity = 1
		}

		q := database.DB.Where("id NOT IN (?)", subQ)

		if ticket.Region != "" && ticket.Region != "不限" {
			matchedRegionID := ""
			for rid, rname := range regionNameMap {
				if rname == ticket.Region {
					matchedRegionID = rid
					break
				}
			}
			if matchedRegionID != "" {
				q = q.Where("region_id = ?", matchedRegionID)
			}
		}

		if groupFilter != "" && groupFilter != "全部" {
			q = q.Where("group_name = ?", groupFilter)
		}

		q.Limit(quantity).Find(&toAssign)
	}

	if len(toAssign) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "没有可用的未分配实例"})
		return
	}

	assigned := 0
	for _, inst := range toAssign {
		if err := database.DB.Create(&models.UserInstance{
			UserID:     ticket.UserID,
			InstanceID: inst.ID,
		}).Error; err == nil {
			assigned++
		}
	}

	if assigned == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "分配失败，所选实例可能已被分配"})
		return
	}

	ticket.Status = "completed"
	now := time.Now()
	ticket.ReviewedAt = &now
	ticket.AdminReply = fmt.Sprintf("%s\n已分配 %d 台实例", ticket.AdminReply, assigned)
	database.DB.Save(&ticket)

	logOperation("ticket_assign", fmt.Sprintf("工单 #%d: 为用户 %s 分配 %d 台实例", ticket.ID, ticket.User.Username, assigned), nil, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("成功分配 %d 台实例", assigned), "assigned": assigned})
}
