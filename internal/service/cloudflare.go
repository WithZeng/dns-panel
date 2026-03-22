package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type CloudflareManager struct {
	APIToken string
	client   *http.Client
}

func NewCloudflareManager(apiToken string) *CloudflareManager {
	return &CloudflareManager{
		APIToken: apiToken,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

type cfResponse struct {
	Success bool              `json:"success"`
	Result  json.RawMessage   `json:"result"`
	Errors  []cfError         `json:"errors"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (cm *CloudflareManager) request(method, path string, body any, query url.Values) (json.RawMessage, error) {
	u := "https://api.cloudflare.com/client/v4" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}

	req, _ := http.NewRequest(method, u, bodyReader)
	req.Header.Set("Authorization", "Bearer "+cm.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cm.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cfResp cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !cfResp.Success {
		msgs := ""
		for _, e := range cfResp.Errors {
			msgs += e.Message + "; "
		}
		if msgs == "" {
			msgs = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("cloudflare: %s", msgs)
	}
	return cfResp.Result, nil
}

func (cm *CloudflareManager) ListDNSRecords(zoneID, recordType, name string) ([]DNSRecord, error) {
	q := url.Values{}
	if recordType != "" {
		q.Set("type", recordType)
	}
	if name != "" {
		q.Set("name", name)
	}
	data, err := cm.request("GET", "/zones/"+zoneID+"/dns_records", nil, q)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	json.Unmarshal(data, &records)
	return records, nil
}

func (cm *CloudflareManager) CreateDNSRecord(zoneID, name, recordType, content string, ttl int, proxied bool) (*DNSRecord, error) {
	payload := map[string]any{
		"type": recordType, "name": name, "content": content,
		"ttl": ttl, "proxied": proxied,
	}
	data, err := cm.request("POST", "/zones/"+zoneID+"/dns_records", payload, nil)
	if err != nil {
		return nil, err
	}
	var rec DNSRecord
	json.Unmarshal(data, &rec)
	return &rec, nil
}

func (cm *CloudflareManager) UpdateDNSRecord(zoneID, recordID, name, recordType, content string, ttl int, proxied bool) (*DNSRecord, error) {
	payload := map[string]any{
		"type": recordType, "name": name, "content": content,
		"ttl": ttl, "proxied": proxied,
	}
	data, err := cm.request("PUT", "/zones/"+zoneID+"/dns_records/"+recordID, payload, nil)
	if err != nil {
		return nil, err
	}
	var rec DNSRecord
	json.Unmarshal(data, &rec)
	return &rec, nil
}

func (cm *CloudflareManager) DeleteDNSRecord(zoneID, recordID string) error {
	_, err := cm.request("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil)
	return err
}

func (cm *CloudflareManager) UpsertDNSRecord(zoneID, domain, recordType, content string, ttl int, proxied bool) (*DNSRecord, error) {
	existing, err := cm.ListDNSRecords(zoneID, recordType, domain)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return cm.UpdateDNSRecord(zoneID, existing[0].ID, domain, recordType, content, ttl, proxied)
	}
	return cm.CreateDNSRecord(zoneID, domain, recordType, content, ttl, proxied)
}
