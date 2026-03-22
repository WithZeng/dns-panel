package handler

import (
	"net/http"

	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

func DiscoverPage(c *gin.Context) {
	c.HTML(http.StatusOK, "discover.html", gin.H{"username": c.GetString("username")})
}

func DiscoverPost(c *gin.Context) {
	ak := c.PostForm("access_key_id")
	sk := c.PostForm("access_key_secret")
	regionID := c.PostForm("region_id")
	if regionID == "" {
		regionID = "cn-hangzhou"
	}

	if ak == "" || sk == "" {
		c.HTML(http.StatusOK, "discover.html", gin.H{
			"error":    "请填写 Access Key ID 和 Secret",
			"username": c.GetString("username"),
		})
		return
	}

	client := aliyun.NewClient(ak, sk, regionID)

	type discoveredInst struct {
		InstanceID string `json:"instance_id"`
		Name       string `json:"name"`
		RegionID   string `json:"region_id"`
		Status     string `json:"status"`
		PublicIP   string `json:"public_ip"`
		Added      bool   `json:"already_added"`
	}

	info, err := aliyun.DescribeInstances(client)
	if err != nil {
		c.HTML(http.StatusOK, "discover.html", gin.H{
			"error":    "扫描失败: " + err.Error(),
			"username": c.GetString("username"),
		})
		return
	}

	var discovered []discoveredInst
	for _, inst := range info {
		var existing models.EcsInstance
		added := database.DB.Where("instance_id = ?", inst.InstanceID).First(&existing).Error == nil
		discovered = append(discovered, discoveredInst{
			InstanceID: inst.InstanceID,
			Name:       inst.Name,
			RegionID:   inst.RegionID,
			Status:     inst.Status,
			PublicIP:   inst.PublicIP,
			Added:      added,
		})
	}

	c.HTML(http.StatusOK, "discover.html", gin.H{
		"discovered": discovered,
		"ak":         ak,
		"sk":         sk,
		"region_id":  regionID,
		"username":   c.GetString("username"),
	})
}
