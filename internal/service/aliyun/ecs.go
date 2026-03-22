package aliyun

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type ECSInfo struct {
	Status    string `json:"status"`
	PublicIP  string `json:"public_ip"`
	PrivateIP string `json:"private_ip"`
	IPv6Addr  string `json:"ipv6_addr"`
}

type InstanceBasicInfo struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
	RegionID   string `json:"region_id"`
	Status     string `json:"status"`
	PublicIP   string `json:"public_ip"`
}

func DescribeInstances(c *Client) ([]InstanceBasicInfo, error) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	data, err := c.DoAction(domain, "2014-05-26", "DescribeInstances", map[string]string{
		"PageSize": "100",
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Instances struct {
			Instance []struct {
				InstanceId   string `json:"InstanceId"`
				InstanceName string `json:"InstanceName"`
				RegionId     string `json:"RegionId"`
				Status       string `json:"Status"`
				PublicIP     struct {
					IpAddress []string `json:"IpAddress"`
				} `json:"PublicIpAddress"`
				EipAddress struct {
					IpAddress string `json:"IpAddress"`
				} `json:"EipAddress"`
			} `json:"Instance"`
		} `json:"Instances"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse DescribeInstances: %w", err)
	}

	var result []InstanceBasicInfo
	for _, inst := range resp.Instances.Instance {
		ip := ""
		if len(inst.PublicIP.IpAddress) > 0 {
			ip = inst.PublicIP.IpAddress[0]
		} else if inst.EipAddress.IpAddress != "" {
			ip = inst.EipAddress.IpAddress
		}
		result = append(result, InstanceBasicInfo{
			InstanceID: inst.InstanceId,
			Name:       inst.InstanceName,
			RegionID:   inst.RegionId,
			Status:     inst.Status,
			PublicIP:   ip,
		})
	}
	return result, nil
}

type IPv6Info struct {
	Enabled      bool     `json:"enabled"`
	Addresses    []string `json:"addresses"`
	PrimaryENIID string   `json:"primary_eni_id"`
	Message      string   `json:"message"`
}

func GetIPv6Info(c *Client, instanceID string) (*IPv6Info, error) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	idsJSON, _ := json.Marshal([]string{instanceID})
	data, err := c.DoAction(domain, "2014-05-26", "DescribeInstances", map[string]string{
		"InstanceIds": string(idsJSON),
	})
	if err != nil {
		return &IPv6Info{Message: err.Error()}, nil
	}

	var resp struct {
		Instances struct {
			Instance []struct {
				VpcAttributes struct {
					Ipv6Addresses struct {
						Ipv6Address []string `json:"Ipv6Address"`
					} `json:"Ipv6Addresses"`
				} `json:"VpcAttributes"`
				NetworkInterfaces struct {
					NetworkInterface []struct {
						NetworkInterfaceId string `json:"NetworkInterfaceId"`
						Ipv6Sets           struct {
							Ipv6Set []struct {
								Ipv6Address string `json:"Ipv6Address"`
							} `json:"Ipv6Set"`
						} `json:"Ipv6Sets"`
					} `json:"NetworkInterface"`
				} `json:"NetworkInterfaces"`
			} `json:"Instance"`
		} `json:"Instances"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return &IPv6Info{Message: "parse error"}, nil
	}
	if len(resp.Instances.Instance) == 0 {
		return &IPv6Info{Message: "实例不存在或无权限"}, nil
	}

	inst := resp.Instances.Instance[0]
	info := &IPv6Info{Message: "ok"}

	var addrs []string
	for _, a := range inst.VpcAttributes.Ipv6Addresses.Ipv6Address {
		if a != "" {
			addrs = append(addrs, a)
		}
	}

	var eniID string
	for _, ni := range inst.NetworkInterfaces.NetworkInterface {
		if eniID == "" && ni.NetworkInterfaceId != "" {
			eniID = ni.NetworkInterfaceId
		}
		for _, s := range ni.Ipv6Sets.Ipv6Set {
			if s.Ipv6Address != "" {
				found := false
				for _, existing := range addrs {
					if existing == s.Ipv6Address {
						found = true
						break
					}
				}
				if !found {
					addrs = append(addrs, s.Ipv6Address)
				}
			}
		}
	}

	info.PrimaryENIID = eniID
	info.Addresses = addrs
	info.Enabled = len(addrs) > 0
	return info, nil
}

func EnableIPv6(c *Client, instanceID string) (bool, string, []string) {
	info, err := GetIPv6Info(c, instanceID)
	if err != nil {
		return false, fmt.Sprintf("获取 IPv6 信息失败: %v", err), nil
	}
	if info.Enabled {
		return true, fmt.Sprintf("IPv6 已开启: %s", strings.Join(info.Addresses, ", ")), info.Addresses
	}

	eniID := info.PrimaryENIID
	if eniID == "" {
		return false, fmt.Sprintf("未找到主网卡，无法分配 IPv6（%s）", info.Message), nil
	}

	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	_, err = c.DoAction(domain, "2014-05-26", "AssignIpv6Addresses", map[string]string{
		"NetworkInterfaceId": eniID,
		"Ipv6AddressCount":  "1",
	})
	if err != nil {
		return false, fmt.Sprintf("分配 IPv6 失败: %v", err), nil
	}

	refresh, _ := GetIPv6Info(c, instanceID)
	if refresh != nil && refresh.Enabled {
		return true, fmt.Sprintf("IPv6 已成功开启: %s", strings.Join(refresh.Addresses, ", ")), refresh.Addresses
	}
	return true, "IPv6 分配指令已发送，请稍后刷新查看", nil
}

func ECSStart(c *Client, instanceID string) (bool, string) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	_, err := c.DoAction(domain, "2014-05-26", "StartInstance", map[string]string{
		"InstanceId": instanceID,
	})
	if err != nil {
		log.Printf("[ecs] start failed %s: %v", instanceID, err)
		return false, err.Error()
	}
	return true, "start command sent"
}

func ECSStop(c *Client, instanceID string) (bool, string) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	_, err := c.DoAction(domain, "2014-05-26", "StopInstance", map[string]string{
		"InstanceId": instanceID,
	})
	if err != nil {
		log.Printf("[ecs] stop failed %s: %v", instanceID, err)
		return false, err.Error()
	}
	return true, "stop command sent"
}

func ECSRelease(c *Client, instanceID string) (bool, string) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	_, err := c.DoAction(domain, "2014-05-26", "DeleteInstance", map[string]string{
		"InstanceId": instanceID,
		"Force":      "true",
	})
	if err != nil {
		log.Printf("[ecs] release failed %s: %v", instanceID, err)
		return false, err.Error()
	}
	return true, "instance release success"
}

func GetECSInfo(c *Client, instanceID string) (*ECSInfo, error) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	idsJSON, _ := json.Marshal([]string{instanceID})
	data, err := c.DoAction(domain, "2014-05-26", "DescribeInstances", map[string]string{
		"InstanceIds": string(idsJSON),
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Instances struct {
			Instance []struct {
				Status    string `json:"Status"`
				PublicIP  struct {
					IpAddress []string `json:"IpAddress"`
				} `json:"PublicIpAddress"`
				EipAddress struct {
					IpAddress string `json:"IpAddress"`
				} `json:"EipAddress"`
				VpcAttributes struct {
					PrivateIP struct {
						IpAddress []string `json:"IpAddress"`
					} `json:"PrivateIpAddress"`
					Ipv6Addresses struct {
						Ipv6Address []string `json:"Ipv6Address"`
					} `json:"Ipv6Addresses"`
				} `json:"VpcAttributes"`
				NetworkInterfaces struct {
					NetworkInterface []struct {
						Ipv6Sets struct {
							Ipv6Set []struct {
								Ipv6Address string `json:"Ipv6Address"`
							} `json:"Ipv6Set"`
						} `json:"Ipv6Sets"`
					} `json:"NetworkInterface"`
				} `json:"NetworkInterfaces"`
			} `json:"Instance"`
		} `json:"Instances"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse DescribeInstances: %w", err)
	}

	if len(resp.Instances.Instance) == 0 {
		return nil, nil
	}

	inst := resp.Instances.Instance[0]
	info := &ECSInfo{Status: inst.Status}

	publicIPs := inst.PublicIP.IpAddress
	if inst.EipAddress.IpAddress != "" {
		publicIPs = append(publicIPs, inst.EipAddress.IpAddress)
	}
	if len(publicIPs) > 0 {
		info.PublicIP = publicIPs[0]
	}

	if len(inst.VpcAttributes.PrivateIP.IpAddress) > 0 {
		info.PrivateIP = inst.VpcAttributes.PrivateIP.IpAddress[0]
	}

	ipv6s := inst.VpcAttributes.Ipv6Addresses.Ipv6Address
	if len(ipv6s) == 0 {
		for _, ni := range inst.NetworkInterfaces.NetworkInterface {
			for _, i6 := range ni.Ipv6Sets.Ipv6Set {
				if i6.Ipv6Address != "" {
					ipv6s = append(ipv6s, i6.Ipv6Address)
				}
			}
		}
	}
	if len(ipv6s) > 0 {
		info.IPv6Addr = ipv6s[0]
	}

	return info, nil
}

func GetSecurityGroups(c *Client, instanceID string) ([]string, error) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	idsJSON, _ := json.Marshal([]string{instanceID})
	data, err := c.DoAction(domain, "2014-05-26", "DescribeInstances", map[string]string{
		"InstanceIds": string(idsJSON),
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Instances struct {
			Instance []struct {
				SecurityGroupIds struct {
					SecurityGroupId []string `json:"SecurityGroupId"`
				} `json:"SecurityGroupIds"`
			} `json:"Instance"`
		} `json:"Instances"`
	}
	json.Unmarshal(data, &resp)
	if len(resp.Instances.Instance) == 0 {
		return nil, fmt.Errorf("instance not found")
	}
	return resp.Instances.Instance[0].SecurityGroupIds.SecurityGroupId, nil
}

type SGRule struct {
	IpProtocol     string `json:"IpProtocol"`
	PortRange      string `json:"PortRange"`
	SourceCidrIp   string `json:"SourceCidrIp"`
	Ipv6SourceCidr string `json:"Ipv6SourceCidrIp"`
	Policy         string `json:"Policy"`
	Description    string `json:"Description"`
	Direction      string `json:"Direction"`
}

func DescribeSGRules(c *Client, sgID string) ([]SGRule, error) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	data, err := c.DoAction(domain, "2014-05-26", "DescribeSecurityGroupAttribute", map[string]string{
		"SecurityGroupId": sgID,
		"Direction":       "ingress",
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Permissions struct {
			Permission []SGRule `json:"Permission"`
		} `json:"Permissions"`
	}
	json.Unmarshal(data, &resp)
	return resp.Permissions.Permission, nil
}

func AuthorizeSG(c *Client, sgID, ipProtocol, portRange, sourceCidr, policy, desc string) (bool, string) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	params := map[string]string{
		"SecurityGroupId": sgID,
		"NicType":         "intranet",
		"IpProtocol":      ipProtocol,
		"PortRange":       portRange,
		"Policy":          policy,
	}
	if strings.Contains(sourceCidr, ":") {
		params["Ipv6SourceCidrIp"] = sourceCidr
	} else {
		params["SourceCidrIp"] = sourceCidr
	}
	if desc != "" {
		params["Description"] = desc
	}

	_, err := c.DoAction(domain, "2014-05-26", "AuthorizeSecurityGroup", params)
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && strings.Contains(strings.ToLower(apiErr.Code), "duplicate") {
			return true, "exists"
		}
		return false, err.Error()
	}
	return true, "ok"
}

func RevokeSG(c *Client, sgID, ipProtocol, portRange, sourceCidr, policy string) (bool, string) {
	domain := fmt.Sprintf("ecs.%s.aliyuncs.com", c.RegionID)
	params := map[string]string{
		"SecurityGroupId": sgID,
		"NicType":         "intranet",
		"IpProtocol":      ipProtocol,
		"PortRange":       portRange,
		"Policy":          policy,
	}
	if strings.Contains(sourceCidr, ":") {
		params["Ipv6SourceCidrIp"] = sourceCidr
	} else {
		params["SourceCidrIp"] = sourceCidr
	}

	_, err := c.DoAction(domain, "2014-05-26", "RevokeSecurityGroup", params)
	if err != nil {
		return false, err.Error()
	}
	return true, "ok"
}
