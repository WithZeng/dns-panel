package middleware

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			if isAPIRequest(c) {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}
		c.Set("user_id", userID)
		c.Set("username", session.Get("username"))
		c.Next()
	}
}

func ForcePasswordChange() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if forceChange, ok := session.Get("force_password_change").(bool); ok && forceChange {
			if c.Request.URL.Path != "/change_password" && c.Request.URL.Path != "/logout" {
				c.Redirect(http.StatusFound, "/change_password")
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("%s %s %d %v", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start).Round(time.Millisecond))
	}
}

// Simple in-memory rate limiter
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	count    int
	lastSeen time.Time
}

var limiter = &rateLimiter{visitors: make(map[string]*visitor)}

func RateLimit(maxRequests int, window time.Duration) gin.HandlerFunc {
	go func() {
		for {
			time.Sleep(window)
			limiter.mu.Lock()
			for ip, v := range limiter.visitors {
				if time.Since(v.lastSeen) > window {
					delete(limiter.visitors, ip)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter.mu.Lock()
		v, exists := limiter.visitors[ip]
		if !exists {
			v = &visitor{}
			limiter.visitors[ip] = v
		}
		if time.Since(v.lastSeen) > window {
			v.count = 0
		}
		v.count++
		v.lastSeen = time.Now()
		count := v.count
		limiter.mu.Unlock()

		if count > maxRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "message": "请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func isAPIRequest(c *gin.Context) bool {
	if strings.HasPrefix(c.Request.URL.Path, "/api/") {
		return true
	}
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "application/json")
}
