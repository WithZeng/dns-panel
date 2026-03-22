package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WithZeng/dns-panel/internal/crypto"
	"github.com/WithZeng/dns-panel/internal/database"
	"github.com/WithZeng/dns-panel/internal/models"
	"github.com/WithZeng/dns-panel/internal/service/aliyun"
	"github.com/gin-gonic/gin"
)

func EnableIPv6(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "实例不存在"})
		return
	}

	ak, sk, err := decryptCredentials(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": "凭据解密失败"})
		return
	}

	client := aliyun.NewClient(ak, sk, inst.RegionID)
	success, msg, addrs := aliyun.EnableIPv6(client, inst.InstanceID)

	if success && len(addrs) > 0 {
		inst.IPv6Addr = addrs[0]
		database.DB.Save(&inst)
	}

	logOperation("enable_ipv6", fmt.Sprintf("%s: %s", inst.Name, msg), &inst.ID, c)
	c.JSON(http.StatusOK, gin.H{"success": success, "message": msg, "addresses": addrs})
}

func GetIPv6Status(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false})
		return
	}

	ak, sk, err := decryptCredentials(&inst)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "ipv6_info": map[string]interface{}{
			"enabled": false, "message": "凭据解密失败", "addresses": []string{},
		}})
		return
	}

	client := aliyun.NewClient(ak, sk, inst.RegionID)
	info, _ := aliyun.GetIPv6Info(client, inst.InstanceID)
	if info == nil {
		info = &aliyun.IPv6Info{Message: "查询失败"}
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "ipv6_info": info})
}

func DownloadIPv6Script(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.String(http.StatusNotFound, "实例不存在")
		return
	}

	script := buildIPv6SetupScript(&inst)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=ipv6_setup_%s.sh", inst.InstanceID))
	c.Data(http.StatusOK, "text/x-shellscript", []byte(script))
}

func PublicIPv6Script(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	token := c.Query("token")

	if !verifyIPv6ScriptToken(token, id) {
		c.String(http.StatusForbidden, "IPv6 脚本链接无效或已过期，请回到面板重新生成。")
		return
	}

	var inst models.EcsInstance
	if err := database.DB.First(&inst, id).Error; err != nil {
		c.String(http.StatusForbidden, "实例不存在或已删除。")
		return
	}

	script := buildIPv6SetupScript(&inst)
	c.Data(http.StatusOK, "text/x-shellscript", []byte(script))
}

func generateIPv6ScriptToken(instanceID int) string {
	ts := time.Now().Unix()
	payload := fmt.Sprintf("%d:%d", instanceID, ts)
	mac := hmac.New(sha256.New, []byte(getIPv6TokenSecret()))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%d.%s", ts, sig)
}

func verifyIPv6ScriptToken(token string, instanceID int) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 1800 {
		return false
	}
	payload := fmt.Sprintf("%d:%d", instanceID, ts)
	mac := hmac.New(sha256.New, []byte(getIPv6TokenSecret()))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

func getIPv6TokenSecret() string {
	return "ecs-monitor-ipv6-token-secret"
}

func decryptCredentials(inst *models.EcsInstance) (string, string, error) {
	ak := inst.AccessKeyID
	sk := inst.AccessKeySK
	if inst.IsEncrypted {
		var err error
		ak, err = crypto.Decrypt(ak)
		if err != nil {
			return "", "", err
		}
		sk, err = crypto.Decrypt(sk)
		if err != nil {
			return "", "", err
		}
	}
	return ak, sk, nil
}

func buildIPv6SetupScript(inst *models.EcsInstance) string {
	targetIPv6 := ""
	ak, sk, err := decryptCredentials(inst)
	if err == nil {
		client := aliyun.NewClient(ak, sk, inst.RegionID)
		info, _ := aliyun.GetIPv6Info(client, inst.InstanceID)
		if info != nil && len(info.Addresses) > 0 {
			targetIPv6 = info.Addresses[0]
		}
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

TARGET_IPV6="%s"

echo "[1/5] 启用内核 IPv6 开关"
cat >/etc/sysctl.d/99-enable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
sysctl --system >/dev/null

echo "[2/5] 识别主网卡"
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp)' | head -n1 || true)
fi
if [[ -z "$IFACE" ]]; then
    echo "[ERROR] 无法识别网卡，请手动配置"
    exit 1
fi
echo "网卡: $IFACE"

echo "[3/5] 打开 IPv6 自动配置"
sysctl -w net.ipv6.conf."$IFACE".accept_ra=2 >/dev/null || true
sysctl -w net.ipv6.conf."$IFACE".autoconf=1 >/dev/null || true

echo "[4/5] 尝试通过网络管理器刷新"
if command -v nmcli >/dev/null 2>&1; then
    CONN=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$IFACE" '$2==d {print $1; exit}')
    if [[ -n "$CONN" ]]; then
        nmcli con mod "$CONN" ipv6.method auto || true
        nmcli con up "$CONN" || true
    fi
fi

if command -v netplan >/dev/null 2>&1; then
    NETPLAN_FILE="/etc/netplan/99-ipv6-auto.yaml"
    cat >"$NETPLAN_FILE" <<EOF
network:
    version: 2
    ethernets:
        $IFACE:
            dhcp6: true
            accept-ra: true
EOF
    netplan apply || true
fi

if [[ -n "$TARGET_IPV6" ]] && ! ip -6 addr show dev "$IFACE" | grep -q "$TARGET_IPV6"; then
    echo "[5/5] 添加云端分配的 IPv6 地址: $TARGET_IPV6"
    ip -6 addr add "$TARGET_IPV6/128" dev "$IFACE" || true
fi

if ! ip -6 route show default | grep -q '^default'; then
    echo "[extra] 未检测到默认 IPv6 路由，尝试添加 default via fe80::1 dev $IFACE"
    ip -6 route replace default via fe80::1 dev "$IFACE" metric 1024 || true
fi

echo "完成，当前 IPv6 地址如下："
ip -6 addr show dev "$IFACE"
echo "当前 IPv6 路由如下："
ip -6 route show
echo "开始连通性测试（国内优先目标）..."
TEST_TARGETS=("2400:3200::1" "2400:3200:baba::1" "240c::6666" "240c::6644")
for target in "${TEST_TARGETS[@]}"; do
    echo "- ping6 $target"
    if ping -6 -c 3 -W 2 "$target" >/dev/null 2>&1; then
        echo "  ✅ 可达"
    else
        echo "  ❌ 不可达"
    fi
done
echo "你也可以测试业务域名: ping -6 -c 3 <你的域名>"
`, targetIPv6)
}
