package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var (
	probeConns   = make(map[uint]*websocket.Conn)
	probeConnsMu sync.RWMutex
)

func WSAgent(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	var probe models.ProbeServer
	if err := database.DB.Where("token = ?", token).First(&probe).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[ws] upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	probeConnsMu.Lock()
	if old, ok := probeConns[probe.ID]; ok {
		old.Close()
	}
	probeConns[probe.ID] = conn
	probeConnsMu.Unlock()

	defer func() {
		probeConnsMu.Lock()
		delete(probeConns, probe.ID)
		probeConnsMu.Unlock()
		probe.IsOnline = false
		database.DB.Save(&probe)
	}()

	now := time.Now()
	probe.IsOnline = true
	probe.LastSeen = &now
	database.DB.Save(&probe)
	log.Printf("[ws] agent connected: %s (id=%d)", probe.Name, probe.ID)

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[ws] agent disconnected: %s (%v)", probe.Name, err)
			break
		}

		var report map[string]interface{}
		if err := json.Unmarshal(msg, &report); err != nil {
			continue
		}

		now := time.Now()
		probe.IsOnline = true
		probe.LastSeen = &now

		if v, ok := report["ipv4"].(string); ok {
			probe.IPv4 = v
		}
		if v, ok := report["ipv6"].(string); ok {
			probe.IPv6 = v
		}
		if v, ok := report["cpu_name"].(string); ok {
			probe.CPUName = v
		}
		if v, ok := report["cpu_cores"].(float64); ok {
			probe.CPUCores = int(v)
		}
		if v, ok := report["arch"].(string); ok {
			probe.Arch = v
		}
		if v, ok := report["os"].(string); ok {
			probe.OSInfo = v
		}
		if v, ok := report["virtualization"].(string); ok {
			probe.Virtualization = v
		}
		if v, ok := report["mem_total"].(float64); ok {
			probe.MemTotal = int64(v)
		}
		if v, ok := report["swap_total"].(float64); ok {
			probe.SwapTotal = int64(v)
		}
		if v, ok := report["disk_total"].(float64); ok {
			probe.DiskTotal = int64(v)
		}

		probe.SetLatestReport(report)
		database.DB.Save(&probe)
	}
}
