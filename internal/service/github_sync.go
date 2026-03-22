package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type GitHubSyncPayload struct {
	AccountSlug       string
	AccountIdentifier string
	LoginName         string
	Remark            string
	AccessKeyID       string
	AccessKeySecret   string
	Region            string
	Instances         []GitHubSyncInstance
}

type GitHubSyncInstance struct {
	InstanceID string
	Name       string
	RegionID   string
	Status     string
	PublicIP   string
	PrivateIP  string
	IPv6       string
}

func safeYAML(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func SyncAccountToGitHub(repo string, payload *GitHubSyncPayload) (bool, string) {
	if _, err := exec.LookPath("gh"); err != nil {
		return false, "未检测到 gh CLI，请先安装并执行 gh auth login"
	}

	check := exec.Command("gh", "repo", "view", repo)
	if out, err := check.CombinedOutput(); err != nil {
		create := exec.Command("gh", "repo", "create", repo, "--private", "--confirm")
		if cOut, cErr := create.CombinedOutput(); cErr != nil {
			return false, fmt.Sprintf("创建 GitHub 仓库失败: %s", strings.TrimSpace(string(cOut)))
		}
		_ = out
	}

	filePath := fmt.Sprintf("accounts/%s/account.yaml", payload.AccountSlug)

	var lines []string
	lines = append(lines,
		fmt.Sprintf("account_slug: %s", safeYAML(payload.AccountSlug)),
		fmt.Sprintf("account_identifier: %s", safeYAML(payload.AccountIdentifier)),
		fmt.Sprintf("login_name: %s", safeYAML(payload.LoginName)),
		fmt.Sprintf("remark: %s", safeYAML(payload.Remark)),
		fmt.Sprintf("access_key_id: %s", safeYAML(payload.AccessKeyID)),
		fmt.Sprintf("access_key_secret: %s", safeYAML(payload.AccessKeySecret)),
		fmt.Sprintf("region: %s", safeYAML(payload.Region)),
		fmt.Sprintf("discovered_at: %s", safeYAML(time.Now().UTC().Format("2006-01-02T15:04:05Z"))),
		"instances:",
	)
	for _, inst := range payload.Instances {
		lines = append(lines,
			fmt.Sprintf("  - instance_id: %s", safeYAML(inst.InstanceID)),
			fmt.Sprintf("    name: %s", safeYAML(inst.Name)),
			fmt.Sprintf("    region: %s", safeYAML(inst.RegionID)),
			fmt.Sprintf("    status: %s", safeYAML(inst.Status)),
			fmt.Sprintf("    public_ip: %s", safeYAML(inst.PublicIP)),
			fmt.Sprintf("    private_ip: %s", safeYAML(inst.PrivateIP)),
			fmt.Sprintf("    ipv6: %s", safeYAML(inst.IPv6)),
		)
	}
	content := strings.Join(lines, "\n") + "\n"
	contentB64 := base64.StdEncoding.EncodeToString([]byte(content))

	sha := getFileSHA(repo, filePath)

	cmd := []string{
		"gh", "api", "--method", "PUT",
		fmt.Sprintf("repos/%s/contents/%s", repo, filePath),
		"-f", fmt.Sprintf("message=chore(account-sync): update %s", payload.AccountSlug),
		"-f", fmt.Sprintf("content=%s", contentB64),
		"-f", "branch=main",
	}
	if sha != "" {
		cmd = append(cmd, "-f", fmt.Sprintf("sha=%s", sha))
	}

	putCmd := exec.Command(cmd[0], cmd[1:]...)
	out, err := putCmd.CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("GitHub 同步失败: %s", strings.TrimSpace(string(out)))
	}

	log.Printf("[github-sync] synced %s to %s/%s", payload.AccountSlug, repo, filePath)
	return true, fmt.Sprintf("%s/%s", repo, filePath)
}

func getFileSHA(repo, filePath string) string {
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/contents/%s", repo, filePath))
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var result map[string]interface{}
	if json.Unmarshal(out, &result) == nil {
		if sha, ok := result["sha"].(string); ok {
			return sha
		}
	}
	return ""
}
