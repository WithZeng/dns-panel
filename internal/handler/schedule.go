package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/gin-gonic/gin"
)

func SchedulesPage(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	var schedules []models.ScheduleTask
	database.DB.Where("instance_id = ?", id).Order("hour, minute").Find(&schedules)

	c.HTML(http.StatusOK, "schedules.html", gin.H{
		"instance":  inst,
		"schedules": schedules,
		"username":  c.GetString("username"),
	})
}

func ScheduleCreate(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	hour, _ := strconv.Atoi(c.PostForm("hour"))
	minute, _ := strconv.Atoi(c.PostForm("minute"))
	action := c.PostForm("action")
	daysOfWeek := c.DefaultPostForm("days_of_week", "*")

	task := models.ScheduleTask{
		InstanceID: inst.ID,
		Action:     action,
		Hour:       hour,
		Minute:     minute,
		DaysOfWeek: daysOfWeek,
		Enabled:    true,
	}
	database.DB.Create(&task)
	logOperation("schedule", fmt.Sprintf("添加定时任务 %s %02d:%02d", action, hour, minute), &inst.ID, c)
	c.Redirect(http.StatusFound, fmt.Sprintf("/instance/%d/schedules", id))
}

func ScheduleToggle(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var task models.ScheduleTask
	if err := database.DB.First(&task, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}
	task.Enabled = !task.Enabled
	database.DB.Save(&task)
	c.Redirect(http.StatusFound, fmt.Sprintf("/instance/%d/schedules", task.InstanceID))
}

func ScheduleDelete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var task models.ScheduleTask
	if err := database.DB.First(&task, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}
	instID := task.InstanceID
	database.DB.Delete(&task)
	c.Redirect(http.StatusFound, fmt.Sprintf("/instance/%d/schedules", instID))
}
