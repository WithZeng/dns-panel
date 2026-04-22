package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func LoginPage(c *gin.Context) {
	session := sessions.Default(c)
	if session.Get("user_id") != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{
		"error": c.Query("error"),
	})
}

func LoginPost(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")

	var user models.User
	if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "用户名或密码错误"})
		return
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "账号已锁定，请稍后再试"})
		return
	}

	if !database.CheckPassword(user.PasswordHash, password) {
		user.FailedLoginCount++
		if user.FailedLoginCount >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			user.LockedUntil = &lockUntil
		}
		database.DB.Save(&user)
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "用户名或密码错误"})
		return
	}

	user.FailedLoginCount = 0
	user.LockedUntil = nil
	database.DB.Save(&user)

	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("force_password_change", user.ForcePasswordChange)
	session.Options(sessions.Options{MaxAge: 1800, Path: "/"})
	session.Save()

	if user.ForcePasswordChange {
		c.Redirect(http.StatusFound, "/change_password")
		return
	}
	c.Redirect(http.StatusFound, "/dashboard")
}

func LoginTokenPost(c *gin.Context) {
	token := strings.TrimSpace(c.PostForm("token"))
	if token == "" {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "请输入登录 Token", "tab": "token"})
		return
	}

	var user models.User
	if err := database.DB.Where("login_token = ?", token).First(&user).Error; err != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "Token 无效", "tab": "token"})
		return
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		c.HTML(http.StatusOK, "login.html", gin.H{"error": "账号已锁定，请稍后再试", "tab": "token"})
		return
	}

	user.FailedLoginCount = 0
	user.LockedUntil = nil
	database.DB.Save(&user)

	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("force_password_change", false)
	session.Set("token_login", true)
	session.Options(sessions.Options{MaxAge: 1800, Path: "/"})
	session.Save()

	c.Redirect(http.StatusFound, "/dashboard")
}

func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func ChangePasswordPage(c *gin.Context) {
	session := sessions.Default(c)
	tokenLogin, _ := session.Get("token_login").(bool)
	c.HTML(http.StatusOK, "change_password.html", gin.H{
		"username":   c.GetString("username"),
		"role":       c.GetString("role"),
		"tokenLogin": tokenLogin,
	})
}

func ChangePasswordPost(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	tokenLogin, _ := session.Get("token_login").(bool)

	oldPassword := c.PostForm("old_password")
	newPassword := c.PostForm("new_password")
	confirmPassword := c.PostForm("confirm_password")

	cpData := gin.H{
		"username":   c.GetString("username"),
		"role":       c.GetString("role"),
		"tokenLogin": tokenLogin,
	}
	if newPassword != confirmPassword {
		cpData["error"] = "两次输入的新密码不一致"
		c.HTML(http.StatusOK, "change_password.html", cpData)
		return
	}
	if len(newPassword) < 8 {
		cpData["error"] = "新密码长度至少 8 位"
		c.HTML(http.StatusOK, "change_password.html", cpData)
		return
	}

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	if !tokenLogin {
		if !database.CheckPassword(user.PasswordHash, oldPassword) {
			cpData["error"] = "原密码错误"
			c.HTML(http.StatusOK, "change_password.html", cpData)
			return
		}
	}

	hash, _ := database.HashPassword(newPassword)
	user.PasswordHash = hash
	user.ForcePasswordChange = false
	database.DB.Save(&user)

	session.Set("force_password_change", false)
	session.Set("token_login", false)
	session.Save()

	c.Redirect(http.StatusFound, "/dashboard")
}

func HealthCheck(c *gin.Context) {
	sqlDB, err := database.DB.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "message": err.Error()})
		return
	}
	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
