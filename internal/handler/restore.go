package handler

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

func RestoreDBPage(c *gin.Context) {
	c.HTML(http.StatusOK, "restore_db.html", gin.H{
		"username": c.GetString("username"),
	})
}

func RestoreDBPost(c *gin.Context) {
	file, _, err := c.Request.FormFile("db_file")
	if err != nil {
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username": c.GetString("username"),
			"error":    "请选择数据库文件",
		})
		return
	}
	defer file.Close()

	dbPath := os.Getenv("DNS_PANEL_DB_PATH")
	if dbPath == "" {
		dbPath = "data/panel.db"
	}

	backupPath := dbPath + ".before_restore"
	if _, err := os.Stat(dbPath); err == nil {
		src, _ := os.Open(dbPath)
		if src != nil {
			dst, _ := os.Create(backupPath)
			if dst != nil {
				io.Copy(dst, src)
				dst.Close()
				log.Printf("[restore] Backed up current DB to %s", backupPath)
			}
			src.Close()
		}
	}

	tmpPath := dbPath + ".uploading"
	out, err := os.Create(tmpPath)
	if err != nil {
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username": c.GetString("username"),
			"error":    "创建临时文件失败：" + err.Error(),
		})
		return
	}

	written, err := io.Copy(out, file)
	out.Close()
	if err != nil || written < 100 {
		os.Remove(tmpPath)
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username": c.GetString("username"),
			"error":    "文件上传失败或文件过小",
		})
		return
	}

	header := make([]byte, 16)
	f, _ := os.Open(tmpPath)
	if f != nil {
		f.Read(header)
		f.Close()
	}
	if string(header[:13]) != "SQLite format" {
		os.Remove(tmpPath)
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username": c.GetString("username"),
			"error":    "无效的 SQLite 数据库文件",
		})
		return
	}

	os.MkdirAll(filepath.Dir(dbPath), 0755)
	if err := os.Rename(tmpPath, dbPath); err != nil {
		os.Remove(tmpPath)
		c.HTML(http.StatusOK, "restore_db.html", gin.H{
			"username": c.GetString("username"),
			"error":    "替换数据库失败：" + err.Error(),
		})
		return
	}

	log.Printf("[restore] Database restored from upload (%d bytes), restarting in 2s...", written)

	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	c.HTML(http.StatusOK, "restore_db.html", gin.H{
		"username": c.GetString("username"),
		"flash":    "数据库恢复成功！面板将在 2 秒后重启，请刷新页面并用原数据库的账号密码登录。",
	})
}
