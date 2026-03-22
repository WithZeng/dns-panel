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
