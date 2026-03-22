package aliyun

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type BillingQueryError struct {
	Msg       string
	ErrorCode string
	RawError  string
}

func (e *BillingQueryError) Error() string {
	if e.RawError != "" && e.RawError != e.Msg {
		return fmt.Sprintf("%s（%s）", e.Msg, e.RawError)
	}
	return e.Msg
}

func classifyBillingError(err error) *BillingQueryError {
	raw := strings.ToLower(err.Error())

	switch {
	case containsAny(raw, "invalidaccesskeyid", "signaturedoesnotmatch", "access key id", "ak/sk"):
		return &BillingQueryError{"认证失败：AK/SK 无效或签名不正确", "AUTH_FAILED", err.Error()}
	case containsAny(raw, "forbidden", "unauthorized", "no permission", "accessdenied", "operationdenied"):
		return &BillingQueryError{"权限不足：当前 RAM 权限无法查询账单/CDT 数据", "PERMISSION_DENIED", err.Error()}
	case containsAny(raw, "throttl", "ratelimit", "rate limit", "too many requests"):
		return &BillingQueryError{"请求过于频繁，已限流", "API_RATE_LIMITED", err.Error()}
	case containsAny(raw, "timeout", "timed out", "connection"):
		return &BillingQueryError{"网络连接异常", "NETWORK_ERROR", err.Error()}
	default:
		return &BillingQueryError{"查询 CDT 账单数据失败", "UNKNOWN_ERROR", err.Error()}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func CredentialStatusFromBillingError(err *BillingQueryError) string {
	switch err.ErrorCode {
	case "AUTH_FAILED":
		return "invalid_access_key"
	case "PERMISSION_DENIED":
		return "unauthorized"
	default:
		return "ok"
	}
}

type MonthSummary struct {
	Month       string  `json:"month"`
	Traffic     float64 `json:"traffic"`
	TrafficUnit string  `json:"traffic_unit"`
	Amount      float64 `json:"amount"`
	Currency    string  `json:"currency"`
}

type CDTBillingSummary struct {
	Months       []MonthSummary `json:"months"`
	TotalTraffic float64        `json:"total_traffic"`
	TotalAmount  float64        `json:"total_amount"`
	Currency     string         `json:"currency"`
	Scope        string         `json:"scope"`
	Provider     string         `json:"provider"`
}

func monthKeysForRecentThree() []string {
	now := time.Now().UTC()
	cursor := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	keys := make([]string, 3)
	for i := 2; i >= 0; i-- {
		keys[i] = cursor.Format("2006-01")
		cursor = cursor.AddDate(0, -1, 0)
	}
	return keys
}

func GetTotalTrafficGB(c *Client, regionID string) (float64, error) {
	data, err := c.DoAction("cdt.aliyuncs.com", "2021-08-13", "ListCdtInternetTraffic", nil)
	if err != nil {
		return 0, classifyBillingError(err)
	}

	var resp struct {
		TrafficDetails interface{} `json:"TrafficDetails"`
	}
	json.Unmarshal(data, &resp)

	details := coerceTrafficDetails(resp.TrafficDetails)
	var totalBytes float64
	matched := 0
	for _, d := range details {
		bizRegion := mapStr(d, "BusinessRegionId")
		if bizRegion == "" {
			bizRegion = mapStr(d, "RegionId")
		}
		if regionMatches(regionID, bizRegion) {
			totalBytes += detailTrafficBytes(d)
			matched++
		}
	}

	if matched == 0 && len(details) == 1 {
		totalBytes = detailTrafficBytes(details[0])
	}

	return totalBytes / (1024 * 1024 * 1024), nil
}

func GetCDTThreeMonthBilling(c *Client, instanceID, regionID string) (*CDTBillingSummary, error) {
	monthKeys := monthKeysForRecentThree()
	var allRows []map[string]interface{}

	for _, month := range monthKeys {
		rows, err := queryInstanceBillRows(c, month)
		if err != nil {
			return nil, classifyBillingError(err)
		}
		allRows = append(allRows, rows...)
	}

	summary := buildCDTMonthlySummary(allRows, instanceID, monthKeys)
	summary.Provider = "aliyun_billing_query_instance_bill"

	if instanceID != "" && summary.TotalTraffic <= 0 {
		injectCDTFallback(c, summary, regionID)
	}

	return summary, nil
}

func queryInstanceBillRows(c *Client, monthKey string) ([]map[string]interface{}, error) {
	month := normalizeMonth(monthKey)
	if month == "" {
		return nil, nil
	}

	var rows []map[string]interface{}
	pageNum := 1

	for {
		data, err := c.DoAction("business.aliyuncs.com", "2017-12-14", "QueryInstanceBill", map[string]string{
			"ProductCode":      "cdt",
			"SubscriptionType": "PayAsYouGo",
			"BillingCycle":     month,
			"Granularity":      "MONTHLY",
			"IsBillingItem":    "true",
			"PageNum":          strconv.Itoa(pageNum),
			"PageSize":         "300",
		})
		if err != nil {
			return nil, err
		}

		var resp struct {
			Data struct {
				TotalCount int                      `json:"TotalCount"`
				Items      struct {
					Item []map[string]interface{} `json:"Item"`
				} `json:"Items"`
			} `json:"Data"`
		}
		json.Unmarshal(data, &resp)

		pageItems := resp.Data.Items.Item
		rows = append(rows, pageItems...)

		if len(pageItems) == 0 || len(rows) >= resp.Data.TotalCount || len(pageItems) < 300 {
			break
		}
		pageNum++
	}

	return rows, nil
}

func buildCDTMonthlySummary(rows []map[string]interface{}, instanceID string, monthKeys []string) *CDTBillingSummary {
	byMonth := make(map[string]*MonthSummary)
	for _, m := range monthKeys {
		byMonth[m] = &MonthSummary{Month: m, TrafficUnit: "GB", Currency: "CNY"}
	}

	instanceKey := strings.ToLower(strings.TrimSpace(instanceID))
	sawInstanceDim := false
	scope := "account"

	var cdtRows []map[string]interface{}
	for _, row := range rows {
		if !isCDTBillRow(row) {
			continue
		}
		cdtRows = append(cdtRows, row)
		instNo := mapStr(row, "InstanceID")
		if instNo == "" {
			instNo = mapStr(row, "InstanceId")
		}
		if instNo != "" {
			sawInstanceDim = true
		}
	}

	useAccountFallback := instanceKey != "" && !sawInstanceDim

	for _, row := range cdtRows {
		month := normalizeMonth(firstNonEmpty(mapStr(row, "BillingCycle"), mapStr(row, "BillCycle"), mapStr(row, "BillingDate")))
		ms, ok := byMonth[month]
		if !ok {
			continue
		}

		instNo := strings.ToLower(strings.TrimSpace(firstNonEmpty(mapStr(row, "InstanceID"), mapStr(row, "InstanceId"))))
		if instanceKey != "" && !useAccountFallback && instNo != instanceKey {
			continue
		}
		if instanceKey != "" && instNo == instanceKey {
			scope = "instance"
		}

		ms.Amount += toFloat(row["PretaxAmount"])
		ms.Traffic += usageToTrafficGB(toFloat(row["Usage"]), mapStr(row, "UsageUnit"))
	}

	summary := &CDTBillingSummary{Currency: "CNY", Scope: scope}
	for _, mk := range monthKeys {
		ms := byMonth[mk]
		ms.Traffic = math.Round(ms.Traffic*10000) / 10000
		ms.Amount = math.Round(ms.Amount*10000) / 10000
		summary.Months = append(summary.Months, *ms)
		summary.TotalTraffic += ms.Traffic
		summary.TotalAmount += ms.Amount
	}
	summary.TotalTraffic = math.Round(summary.TotalTraffic*10000) / 10000
	summary.TotalAmount = math.Round(summary.TotalAmount*10000) / 10000
	return summary
}

func injectCDTFallback(c *Client, summary *CDTBillingSummary, regionID string) {
	trafficGB, err := GetTotalTrafficGB(c, regionID)
	if err != nil || trafficGB <= 0 || len(summary.Months) == 0 {
		return
	}
	latest := &summary.Months[len(summary.Months)-1]
	latest.Traffic = math.Max(latest.Traffic, math.Round(trafficGB*10000)/10000)

	var total float64
	for _, m := range summary.Months {
		total += m.Traffic
	}
	summary.TotalTraffic = math.Round(total*10000) / 10000
	summary.Scope = "account_cdt_fallback"
}

func isCDTBillRow(row map[string]interface{}) bool {
	pd := strings.ToLower(mapStr(row, "ProductDetail"))
	pc := strings.ToLower(mapStr(row, "ProductCode"))
	item := strings.ToLower(mapStr(row, "BillItem"))
	return strings.Contains(pd, "cdt") || strings.Contains(pc, "cdt") ||
		strings.Contains(item, "流量") || strings.Contains(item, "traffic")
}

func usageToTrafficGB(usage float64, unit string) float64 {
	if usage <= 0 {
		return 0
	}
	switch strings.ToLower(unit) {
	case "gb", "gbyte", "gbytes", "gib":
		return usage
	case "mb", "mbyte", "mbytes", "mib":
		return usage / 1024
	case "kb", "kbyte", "kbytes", "kib":
		return usage / (1024 * 1024)
	case "tb", "tbyte", "tbytes", "tib":
		return usage * 1024
	case "byte", "bytes", "b":
		return usage / (1024 * 1024 * 1024)
	default:
		return usage / (1024 * 1024 * 1024)
	}
}

func normalizeMonth(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 6 {
		return s[:4] + "-" + s[4:6]
	}
	if len(s) >= 7 && s[4] == '-' {
		return s[:7]
	}
	return s
}

func regionMatches(target, detail string) bool {
	t := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(target), "_", "-"))
	d := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(detail), "_", "-"))
	if t == "" || d == "" {
		return false
	}
	return t == d || strings.Contains(t, d) || strings.Contains(d, t)
}

func coerceTrafficDetails(raw interface{}) []map[string]interface{} {
	switch v := raw.(type) {
	case []interface{}:
		var out []map[string]interface{}
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]interface{}:
		for _, key := range []string{"TrafficDetail", "TrafficDetails", "Items", "Item"} {
			if nested, ok := v[key]; ok {
				return coerceTrafficDetails(nested)
			}
		}
		return []map[string]interface{}{v}
	}
	return nil
}

func detailTrafficBytes(detail map[string]interface{}) float64 {
	total := toFloat(detail["Traffic"])
	if total > 0 {
		return total
	}
	products := coerceTrafficDetails(detail["ProductTrafficDetails"])
	for _, p := range products {
		total += toFloat(p["Traffic"])
	}
	return total
}

func mapStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	case json.Number:
		f, _ := val.Float64()
		return f
	}
	return 0
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
