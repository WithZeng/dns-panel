package aliyun

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	AccessKeyID     string
	AccessKeySecret string
	RegionID        string
	httpClient      *http.Client
}

func NewClient(ak, sk, region string) *Client {
	return &Client{
		AccessKeyID:     ak,
		AccessKeySecret: sk,
		RegionID:        region,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Aliyun API error [%s]: %s (RequestId: %s)", e.Code, e.Message, e.RequestID)
}

func (c *Client) DoAction(domain, version, action string, params map[string]string) (json.RawMessage, error) {
	if params == nil {
		params = make(map[string]string)
	}

	params["Format"] = "JSON"
	params["Version"] = version
	params["AccessKeyId"] = c.AccessKeyID
	params["SignatureMethod"] = "HMAC-SHA1"
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = uuid.New().String()
	params["Action"] = action

	if _, ok := params["RegionId"]; !ok && c.RegionID != "" {
		params["RegionId"] = c.RegionID
	}

	signature := signRequest("POST", params, c.AccessKeySecret+"&")
	params["Signature"] = signature

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	req, _ := http.NewRequest("POST", "https://"+domain, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", domain, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if codeRaw, ok := result["Code"]; ok {
		var code string
		json.Unmarshal(codeRaw, &code)
		if code != "" && !strings.EqualFold(code, "Success") && !strings.EqualFold(code, "0") {
			var msg, reqID string
			if m, ok := result["Message"]; ok {
				json.Unmarshal(m, &msg)
			}
			if r, ok := result["RequestId"]; ok {
				json.Unmarshal(r, &reqID)
			}
			return nil, &APIError{Code: code, Message: msg, RequestID: reqID}
		}
	}

	return body, nil
}

func signRequest(method string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalized strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalized.WriteByte('&')
		}
		canonicalized.WriteString(specialURLEncode(k))
		canonicalized.WriteByte('=')
		canonicalized.WriteString(specialURLEncode(params[k]))
	}

	stringToSign := method + "&" + specialURLEncode("/") + "&" + specialURLEncode(canonicalized.String())

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func specialURLEncode(s string) string {
	encoded := url.QueryEscape(s)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}
