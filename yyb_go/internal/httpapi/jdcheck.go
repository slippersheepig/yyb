package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"yyb_go/internal/store"
)

// JDCheckResult is the result returned to the frontend after a JD verification attempt.
type JDCheckResult struct {
	Status       string `json:"status"`              // "ok", "risk", "error"
	Message      string `json:"message,omitempty"`   // human-readable message
	RiskURL      string `json:"risk_url,omitempty"`  // JD risk verification URL
	RiskExpireAt int64  `json:"risk_expire_at,omitempty"`
	PTKey        string `json:"pt_key,omitempty"`
	Pin          string `json:"pt_pin,omitempty"`
	JdCookie     string `json:"jd_cookie,omitempty"`
}

// riskURLTTL is the frontend expiry time for a JD risk verification link.
const riskURLTTL = 30 * time.Minute

// autopostTimeout is the maximum time to wait for the autopost service to complete.
const autopostTimeout = 120 * time.Second

// autopostRequest is the JSON body sent to the autopost service.
type autopostRequest struct {
	YYBServer string `json:"yyb_server"`
	Ref       string `json:"ref"`
	AppID     string `json:"app_id,omitempty"`
}

// autopostResponse is the JSON response from the autopost service.
type autopostResponse struct {
	Status   string `json:"status"`
	JdCookie string `json:"jd_cookie,omitempty"`
	RiskURL  string `json:"risk_url,omitempty"`
	Message  string `json:"message,omitempty"`
	PtPin    string `json:"pt_pin,omitempty"`
}

// callAutopost sends a JD verification request to the autopost service and
// returns the result. The autopost service runs JDCode.py's logic from a
// different IP to avoid JD's IP-based risk control.
func (a *App) callAutopost(ctx context.Context, acc *store.WechatAccount) (JDCheckResult, error) {
	if a.cfg.AutopostURL == "" {
		return JDCheckResult{
			Status:  "error",
			Message: "autopost 服务未配置，请联系管理员设置 AUTORPOST_URL 环境变量",
		}, fmt.Errorf("autopost URL not configured")
	}

	// Build the yyb server URL that autopost will call back to.
	// Use the configured WebDomain if set, otherwise fall back to the
	// server's own listening address.
	yybServer := a.cfg.WebDomain
	if yybServer == "" {
		yybServer = fmt.Sprintf("http://127.0.0.1:%d", a.cfg.ListenPort)
	}

	// Resolve ref: use openid (most reliable for cross-service calls).
	ref := acc.OpenID

	reqBody := autopostRequest{
		YYBServer: yybServer,
		Ref:       ref,
	}

	bodyBytes, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.AutopostURL+"/api/jd-check", bytes.NewReader(bodyBytes))
	if err != nil {
		return JDCheckResult{Status: "error", Message: "构建 autopost 请求失败"}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Auth to autopost
	if a.cfg.AutopostToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.cfg.AutopostToken)
	}

	// Also pass YYB_API_TOKEN as a custom header so autopost can use it
	// when calling back to yyb server.
	if a.cfg.APIToken != "" {
		httpReq.Header.Set("X-YYB-API-Token", a.cfg.APIToken)
	}

	client := &http.Client{Timeout: autopostTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[autopost] 请求失败: %v", err)
		return JDCheckResult{
			Status:  "error",
			Message: "autopost 服务连接失败: " + err.Error(),
		}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[autopost] HTTP %d: %s", resp.StatusCode, string(respBody))
		return JDCheckResult{
			Status:  "error",
			Message: fmt.Sprintf("autopost 返回 HTTP %d", resp.StatusCode),
		}, fmt.Errorf("autopost HTTP %d", resp.StatusCode)
	}

	var apResp autopostResponse
	if err := json.Unmarshal(respBody, &apResp); err != nil {
		return JDCheckResult{
			Status:  "error",
			Message: "autopost 响应解析失败",
		}, err
	}

	result := JDCheckResult{
		Status:   apResp.Status,
		JdCookie: apResp.JdCookie,
		RiskURL:  apResp.RiskURL,
		Pin:      apResp.PtPin,
	}

	switch apResp.Status {
	case "ok":
		result.Message = "京东登录成功"
		// Parse pt_key from cookie string for frontend display.
		result.PTKey = parseCookieValue(apResp.JdCookie, "pt_key")
		if result.Pin == "" {
			result.Pin = parseCookieValue(apResp.JdCookie, "pt_pin")
		}
		_ = a.db.SetJdRiskURL(ctx, acc.ID, "")

	case "risk":
		result.RiskExpireAt = time.Now().Add(riskURLTTL).Unix()
		result.Message = "京东返回二验，请点击下方链接完成认证后重新验证"
		if apResp.RiskURL != "" {
			_ = a.db.SetJdRiskURLWithExpiry(ctx, acc.ID, apResp.RiskURL, riskURLTTL)
		}

	case "error", "":
		result.Status = "error"
		if apResp.Message != "" {
			result.Message = apResp.Message
		} else {
			result.Message = "京东返回未知错误"
		}

	default:
		result.Status = "error"
		result.Message = "京东返回未知状态: " + apResp.Status
	}

	return result, nil
}

// parseCookieValue extracts a key=value pair from a cookie string like
// "pt_key=abc;pt_pin=xyz;".
func parseCookieValue(cookieStr, key string) string {
	prefix := key + "="
	for _, part := range splitCookie(cookieStr) {
		part = trimSpace(part)
		if len(part) > len(prefix) && part[:len(prefix)] == prefix {
			return part[len(prefix):]
		}
	}
	return ""
}

func splitCookie(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == ';' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// ── handleMyJdCheck ──

func (a *App) handleMyJdCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, _ := getCookie(r, "yyb_user")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "未登录")
		return
	}
	sess, err := a.db.GetUserSession(r.Context(), token)
	if err != nil || sess == nil {
		writeError(w, http.StatusUnauthorized, "会话已过期")
		return
	}

	var body struct {
		Ref string `json:"ref"`
	}
	_ = decodeOptionalJSON(r, &body)

	var acc *store.WechatAccount
	adminCookie, _ := getCookie(r, "yyb_admin")
	if adminCookie != "" && a.webAuth.IsValidAdmin(adminCookie) && body.Ref != "" {
		acc, err = a.db.ResolveAccount(r.Context(), body.Ref)
	} else {
		acc, err = a.db.GetAccount(r.Context(), sess.WechatAccountID)
	}
	if err != nil || acc == nil {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}

	result, _ := a.callAutopost(r.Context(), acc)

	if result.Status == "error" {
		result.Message += "\n您也可以尝试打开“京东购物”微信小程序，右下角点“我的”-右上角点“设置”-页面拉到底，点击“退出”，重新登录后返回此页面点击「重新扫码」。"
	}

	// Push notification via WeChat if configured.
	a.pushWxNotification(acc.ID, "jd_check", result.Message)

	writeJSON(w, http.StatusOK, result)
}

// ── handleMyJdCookie ──

// handleMyJdCookie always returns empty — YYB does not persist JD CK to DB.
func (a *App) handleMyJdCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jd_cookie":  "",
		"has_cookie": false,
	})
}

// ── helpers ──

func (a *App) pushWxNotification(accountID int64, msgType, content string) {
	if content == "" {
		return
	}
	_, err := a.db.PushWxMessage(context.Background(), accountID, msgType, content)
	if err != nil {
		log.Printf("[wx-push] failed to push wx message for account %d: %v", accountID, err)
	}
}
