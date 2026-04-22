package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

type userWithCount struct {
	models.User
	InstanceCount int64
}

func UserListPage(c *gin.Context) {
	var users []models.User
	database.DB.Where("role != 'admin'").Order("created_at DESC").Find(&users)

	result := make([]userWithCount, 0, len(users))
	for _, u := range users {
		var count int64
		database.DB.Model(&models.UserInstance{}).Where("user_id = ?", u.ID).Count(&count)
		result = append(result, userWithCount{User: u, InstanceCount: count})
	}

	tokenMap := make(map[uint]string)
	for _, u := range users {
		tokenMap[u.ID] = u.LoginToken
	}

	var admin models.User
	database.DB.Where("username = ? AND role = ?", "admin", "admin").First(&admin)

	c.HTML(http.StatusOK, "user_manage.html", gin.H{
		"username":   c.GetString("username"),
		"role":       c.GetString("role"),
		"users":      result,
		"tokenMap":   tokenMap,
		"adminToken": admin.LoginToken,
		"adminID":    admin.ID,
	})
}

func CreateUserPost(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))

	if username == "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "用户名不能为空"})
		return
	}

	var existing models.User
	if database.DB.Where("username = ?", username).First(&existing).Error == nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "用户名已存在"})
		return
	}

	randomPwd := database.GenerateLoginToken()
	hash, _ := database.HashPassword(randomPwd)
	token := database.GenerateLoginToken()

	user := models.User{
		Username:     username,
		PasswordHash: hash,
		LoginToken:   token,
		Role:         "user",
	}
	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": fmt.Sprintf("创建失败: %v", err)})
		return
	}

	logOperation("create_user", fmt.Sprintf("创建用户 %s", username), nil, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "token": token, "username": username})
}

func DeleteUserPost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "用户不存在"})
		return
	}
	if user.Role == "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "不能删除管理员"})
		return
	}

	database.DB.Where("user_id = ?", user.ID).Delete(&models.UserInstance{})
	database.DB.Delete(&user)
	logOperation("delete_user", fmt.Sprintf("删除用户 %s", user.Username), nil, c)
	c.Redirect(http.StatusFound, "/admin/users")
}

func ResetUserPasswordPost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "用户不存在"})
		return
	}

	var body struct {
		Password string `json:"password" form:"password"`
	}
	if c.ContentType() == "application/json" {
		c.BindJSON(&body)
	} else {
		body.Password = c.PostForm("password")
	}

	if len(body.Password) < 8 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "密码长度至少 8 位"})
		return
	}

	hash, _ := database.HashPassword(body.Password)
	user.PasswordHash = hash
	user.ForcePasswordChange = true
	database.DB.Save(&user)

	logOperation("reset_user_password", fmt.Sprintf("重置用户 %s 密码", user.Username), nil, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "密码已重置"})
}

func RegenerateToken(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "用户不存在"})
		return
	}

	newToken := database.GenerateLoginToken()
	user.LoginToken = newToken
	database.DB.Save(&user)

	logOperation("regenerate_token", fmt.Sprintf("重新生成用户 %s 的登录 Token", user.Username), nil, c)
	c.JSON(http.StatusOK, gin.H{"success": true, "token": newToken})
}

func AssignInstancePage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/admin/users")
		return
	}

	var allInstances []models.EcsInstance
	database.DB.Order("group_name, tag, name").Find(&allInstances)

	var assigned []models.UserInstance
	database.DB.Where("user_id = ?", user.ID).Find(&assigned)
	assignedMap := make(map[uint]bool)
	for _, a := range assigned {
		assignedMap[a.InstanceID] = true
	}

	var allAssignments []models.UserInstance
	database.DB.Find(&allAssignments)
	assignedToAny := make(map[uint]bool)
	assignedUser := make(map[uint]string)
	for _, a := range allAssignments {
		assignedToAny[a.InstanceID] = true
	}
	for instID := range assignedToAny {
		var ui models.UserInstance
		if database.DB.Preload("User").Where("instance_id = ?", instID).First(&ui).Error == nil {
			assignedUser[instID] = ui.User.Username
		}
	}

	groups := make(map[string]bool)
	for _, inst := range allInstances {
		if inst.GroupName != "" {
			groups[inst.GroupName] = true
		}
	}
	groupList := make([]string, 0, len(groups))
	for g := range groups {
		groupList = append(groupList, g)
	}

	c.HTML(http.StatusOK, "user_assign.html", gin.H{
		"username":      c.GetString("username"),
		"role":          c.GetString("role"),
		"target_user":   user,
		"instances":     allInstances,
		"assigned":      assignedMap,
		"assigned_any":  assignedToAny,
		"assigned_user": assignedUser,
		"groups":        groupList,
	})
}

func UpdateInstanceGroup(c *gin.Context) {
	var body struct {
		InstanceID uint   `json:"instance_id"`
		GroupName  string `json:"group_name"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "参数错误"})
		return
	}
	if err := database.DB.Model(&models.EcsInstance{}).Where("id = ?", body.InstanceID).Update("group_name", body.GroupName).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func BatchUpdateInstanceGroup(c *gin.Context) {
	var body struct {
		InstanceIDs []uint `json:"instance_ids"`
		GroupName   string `json:"group_name"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "参数错误"})
		return
	}
	if len(body.InstanceIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "未选择实例"})
		return
	}
	database.DB.Model(&models.EcsInstance{}).Where("id IN ?", body.InstanceIDs).Update("group_name", body.GroupName)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": fmt.Sprintf("已更新 %d 个实例的分组", len(body.InstanceIDs))})
}

func AssignInstancePost(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/admin/users")
		return
	}

	c.Request.ParseForm()
	selectedIDs := c.PostFormArray("instance_ids")

	database.DB.Where("user_id = ?", user.ID).Delete(&models.UserInstance{})

	for _, idStr := range selectedIDs {
		instID, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		database.DB.Create(&models.UserInstance{
			UserID:     user.ID,
			InstanceID: uint(instID),
		})
	}

	logOperation("assign_instances", fmt.Sprintf("为用户 %s 分配 %d 个实例", user.Username, len(selectedIDs)), nil, c)
	c.Redirect(http.StatusFound, "/admin/users")
}
