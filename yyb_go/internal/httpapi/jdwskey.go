package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yyb_go/internal/store"
)

const JDAppID = "wx91d27dbf599dff74"

// ── jdWskeyGetPayload is the JSON body for POST /wxapp/getJdWskey ──

type jdWskeyGetRequest struct {
	Ref   string `json:"ref"`
	AppID string `json:"app_id"`
}

// ── handleJdWskeyGet ──
// POST /wxapp/getJdWskey
// 在应用宝扫码登录后，从京东小程序内部存储/API 获取 wskey。
// wskey 是京东用于长期保活的 websocket 令牌，后续可通过 jdback 的
// /api/jd-wskey 接口将 wskey 转换为 pt_key/pt_pin cookie。
//
// Body:
//
//	{
//	  "ref":    "openid 或 UIN",         // 必填
//	  "app_id": "wx91d27dbf599dff74"     // 可选，默认京东小程序
//	}
//
// Response:
//
//	{
//	  "code": 0,
//	  "data": {
//	    "openid": "oXXXX...",
//	    "wskey":  "AAJ..."
//	  }
//	}
func (a *App) handleJdWskeyGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body jdWskeyGetRequest
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}
	if body.AppID == "" {
		body.AppID = JDAppID
	}

	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}

	// 0. 先读数据库：已录入的 wskey 直接返回。
	// 录入入口是 POST /api/my/jd-wskey/import（京东 APP 抓包获取）。
	// 注：微信侧没有可用的 wskey 获取途径——小程序 storage 里不会有京东 APP 的
	// wskey，genToken 也必须有京东登录态才肯发 token；下面的 storage/genToken
	// 尝试仅作兼容保留，正常情况下走不到成功分支。
	if stored, dbErr := a.db.GetJdWskey(r.Context(), acc.ID); dbErr == nil && strings.TrimSpace(stored) != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"openid": acc.OpenID,
			"wskey":  strings.TrimSpace(stored),
			"source": "db",
		})
		return
	}

	// 1. 先尝试从 JD 小程序 wx.Storage 读取 wskey
	wskey, err := a.retrieveJdWskeyFromStorage(r.Context(), acc, body.AppID)
	if err != nil {
		log.Printf("[jdwskey] storage read failed for account %d (%s): %v", acc.ID, acc.OpenID, err)
		// 2. 回退：尝试通过 JD genToken 接口获取
		wskey, err = a.retrieveJdWskeyFromGenToken(r.Context(), acc, body.AppID)
		if err != nil {
			log.Printf("[jdwskey] genToken fallback also failed for account %d (%s): %v", acc.ID, acc.OpenID, err)
			writeError(w, http.StatusBadGateway, "无法获取京东 wskey："+err.Error())
			return
		}
	}

	wskey = strings.TrimSpace(wskey)
	if wskey == "" {
		writeError(w, http.StatusNotFound, "京东小程序未返回 wskey，请确认账号已在京东小程序内登录")
		return
	}

	// 持久化 wskey 到数据库
	if err := a.db.SetJdWskey(r.Context(), acc.ID, wskey); err != nil {
		log.Printf("[jdwskey] failed to store wskey for account %d: %v", acc.ID, err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"openid": acc.OpenID,
		"wskey":  wskey,
	})
}

// ── handleMyJdWskey ──
// GET /api/my/jd-wskey
// 用户前端页面获取已存储的 wskey。
func (a *App) handleMyJdWskey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	var acc *store.WechatAccount
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	adminCookie, _ := getCookie(r, "yyb_admin")
	if adminCookie != "" && a.webAuth.IsValidAdmin(adminCookie) && ref != "" {
		acc, err = a.db.ResolveAccount(r.Context(), ref)
	} else {
		acc, err = a.db.GetAccount(r.Context(), sess.WechatAccountID)
	}
	if err != nil || acc == nil {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}

	wskey, err := a.db.GetJdWskey(r.Context(), acc.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取 wskey 失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"openid":   acc.OpenID,
		"wskey":    wskey,
		"has_key":  wskey != "",
	})
}

// ── retrieveJdWskeyFromStorage ──
// 通过 wx.Storage 读取京东小程序存储的 wskey。
// 京东小程序登录后会将 wskey 写入 wx.Storage，key 为 "wskey"。
func (a *App) retrieveJdWskeyFromStorage(ctx context.Context, acc *store.WechatAccount, appID string) (string, error) {
	// 尝试多个可能的 storage key
	storageKeys := []string{
		"wskey", "jd_wskey", "wskey_jd", "__wskey", 
		"JD_WSKEY", "jdWskey", "ws_key", "token", "tokenKey",
	}

	for _, key := range storageKeys {
		payload := map[string]any{
			"api_name": "getStorage",
			"data": map[string]any{
				"key": key,
			},
			"env": 1,
		}

		result, err := a.invokeWXApp(ctx, acc, appID, payload, a.makeOperateWXDataCall)
		if err != nil {
			continue // 尝试下一个 key
		}

		// 尝试多个响应结构提取 value
		if strVal := extractString(result, "data", "data"); strVal != "" {
			return strVal, nil
		}
		if strVal := extractString(result, "data"); strVal != "" {
			return strVal, nil
		}
		if strVal := extractString(result, "result", "data"); strVal != "" {
			return strVal, nil
		}
	}

	return "", fmt.Errorf("从 wx.Storage 未找到 wskey（已尝试 keys: %v）", storageKeys)
}

// ── retrieveJdWskeyFromGenToken ──
// 通过京东 genToken API（action=from）从当前 session 提取 wskey。
// 这是 JD 官方从当前登录会话导出令牌的接口。
func (a *App) retrieveJdWskeyFromGenToken(ctx context.Context, acc *store.WechatAccount, appID string) (string, error) {
	// 通过 operateWxData 调用 JD 的 genToken API
	bodyStr := fmt.Sprintf("action=from&appid=jd_android&client=android&clientVersion=13.6.4&t=%d", time.Now().UnixMilli())
	
	payload := map[string]any{
		"api_name": "webapi",
		"data": map[string]any{
			"url":    "https://api.m.jd.com/client.action?functionId=genToken",
			"method": "POST",
			"data":   bodyStr,
			"headers": map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent":   "JD4Android/13.6.4",
			},
		},
		"env": 1,
	}

	result, err := a.invokeWXApp(ctx, acc, appID, payload, a.makeOperateWXDataCall)
	if err != nil {
		return "", fmt.Errorf("genToken api call failed: %w", err)
	}

	// 尝试多层解析返回的 token
	for _, path := range [][]string{
		{"data", "token"},
		{"data", "data", "token"},
		{"result", "data", "token"},
		{"token"},
		{"data", "wskey"},
	} {
		if val := extractString(result, path...); val != "" {
			return val, nil
		}
	}
	
	// 把京东返回的具体内容序列化成字符串，方便在 502 报错时直接展示给用户
	resultJSON, _ := json.Marshal(result)
	return "", fmt.Errorf("genToken 响应中未找到 token/wskey。京东原样返回: %s", string(resultJSON))
}

// ── handleJdWskeyImport ──
// POST /api/my/jd-wskey/import
// 手动录入京东 wskey（京东 APP 抓包/VNET 获取，AAJ 开头）。
// 微信扫码侧无法直接获取 wskey，这是唯一的录入途径；录入后
// /wxapp/getJdWskey 会直接返回 DB 值，JDCode.py 的 wskey 链即可跑通。
// Body: {"wskey": "AAJ...", "ref": "可选，管理员指定账号"}
func (a *App) handleJdWskeyImport(w http.ResponseWriter, r *http.Request) {
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
		Ref   string `json:"ref"`
		Wskey string `json:"wskey"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	wskey := strings.TrimSpace(body.Wskey)
	if wskey == "" {
		writeError(w, http.StatusBadRequest, "wskey is required")
		return
	}
	if !strings.HasPrefix(wskey, "AAJ") {
		writeError(w, http.StatusBadRequest, "wskey 格式异常（正常以 AAJ 开头），请确认是京东 APP 抓包得到的 wskey")
		return
	}

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

	if err := a.db.SetJdWskey(r.Context(), acc.ID, wskey); err != nil {
		writeError(w, http.StatusInternalServerError, "保存 wskey 失败")
		return
	}

	// 录入后立即调 jdback 验活：确认 wskey 能换出 30 天 app_open pt_key。
	result := map[string]any{
		"openid":   acc.OpenID,
		"saved":    true,
		"verified": false,
	}
	if exchange, exErr := a.callJdbackWskeyExchange(r.Context(), wskey); exErr == nil && exchange.Status == "ok" {
		result["verified"] = true
		result["pt_pin"] = exchange.PtPin
		result["pt_key_type"] = "app_open"
		if exchange.JdCookie != "" {
			_ = a.db.SetJdCookie(r.Context(), acc.ID, exchange.JdCookie)
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// ── handleJdWskeyRefresh ──
// POST /api/my/jd-wskey/refresh
// 手动触发 wskey 刷新（重新从 JD 小程序获取）。
func (a *App) handleJdWskeyRefresh(w http.ResponseWriter, r *http.Request) {
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

	appID := JDAppID
	wskey, err := a.retrieveJdWskeyFromStorage(r.Context(), acc, appID)
	if err != nil {
		wskey, err = a.retrieveJdWskeyFromGenToken(r.Context(), acc, appID)
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "刷新 wskey 失败："+err.Error())
		return
	}

	wskey = strings.TrimSpace(wskey)
	if wskey == "" {
		writeError(w, http.StatusNotFound, "京东小程序未返回 wskey，请确认账号已在京东小程序内登录")
		return
	}

	if err := a.db.SetJdWskey(r.Context(), acc.ID, wskey); err != nil {
		log.Printf("[jdwskey] refresh: failed to store wskey for account %d: %v", acc.ID, err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"openid": acc.OpenID,
		"wskey":  wskey,
	})
}

// ── helpers ──

// makeOperateWXDataCall returns a wxappCall that calls pool.OperateWXData.
func (a *App) makeOperateWXDataCall(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error) {
	return a.pool.OperateWXData(ctx, acc.LoginBuffer, appID, payload, acc.ID, a.cfg.TCPProxy)
}

// extractString recursively extracts a string value from a nested map by following keys.
func extractString(data map[string]any, keys ...string) string {
	current := any(data)
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
		if current == nil {
			return ""
		}
	}
	if s, ok := current.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// ── JD Wskey → Cookie 转发（调用 jdback 服务）──

const jdWskeyTimeout = 60 * time.Second

// jdWskeyExchangeRequest is sent to jdback /api/jd-wskey
type jdWskeyExchangeRequest struct {
	Wskey string `json:"wskey"`
}

// jdWskeyExchangeResponse from jdback
type jdWskeyExchangeResponse struct {
	Status   string `json:"status"`
	JdCookie string `json:"jd_cookie,omitempty"`
	Message  string `json:"message,omitempty"`
	PtPin    string `json:"pt_pin,omitempty"`
}

// handleMyJdWskeyExchange forwards a wskey to the jdback service to convert to JD cookies.
// POST /api/my/jd-wskey/exchange
// Body: {"wskey": "AAJ..."}  (可选；不传则从 DB 读取已存储的 wskey)
func (a *App) handleMyJdWskeyExchange(w http.ResponseWriter, r *http.Request) {
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
		Ref   string `json:"ref"`
		Wskey string `json:"wskey"`
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

	wskey := strings.TrimSpace(body.Wskey)
	if wskey == "" {
		// 从数据库读取已存储的 wskey
		wskey, err = a.db.GetJdWskey(r.Context(), acc.ID)
		if err != nil || wskey == "" {
			writeError(w, http.StatusBadRequest, "未提供 wskey，且数据库中无已存储的 wskey，请先获取 wskey")
			return
		}
	}

	result, err := a.callJdbackWskeyExchange(r.Context(), wskey)
	if err != nil {
		writeError(w, http.StatusBadGateway, "wskey 转 cookie 失败："+err.Error())
		return
	}

	// 成功后保存 cookie 到数据库
	if result.JdCookie != "" {
		_ = a.db.SetJdCookie(r.Context(), acc.ID, result.JdCookie)
	}

	jdResult := JDCheckResult{
		Status:   result.Status,
		JdCookie: result.JdCookie,
		Message:  result.Message,
		Pin:      result.PtPin,
	}
	if jdResult.Status == "ok" {
		jdResult.PTKey = parseCookieValue(result.JdCookie, "pt_key")
		if jdResult.Pin == "" {
			jdResult.Pin = parseCookieValue(result.JdCookie, "pt_pin")
		}
	}

	writeJSON(w, http.StatusOK, jdResult)
}

// callJdbackWskeyExchange sends a wskey exchange request to the autopost (jdback) service.
func (a *App) callJdbackWskeyExchange(ctx context.Context, wskey string) (jdWskeyExchangeResponse, error) {
	if a.cfg.AutopostURL == "" {
		return jdWskeyExchangeResponse{
			Status:  "error",
			Message: "autopost 服务未配置，请联系管理员设置 AUTORPOST_URL 环境变量",
		}, fmt.Errorf("autopost URL not configured")
	}

	autopostURL, err := validatedAutopostURL(a.cfg.AutopostURL)
	if err != nil {
		return jdWskeyExchangeResponse{Status: "error", Message: "autopost 服务地址配置不安全或无效"}, err
	}

	reqBody := jdWskeyExchangeRequest{Wskey: wskey}
	bodyBytes, _ := json.Marshal(reqBody)

	autopostURL.Path = strings.TrimRight(autopostURL.Path, "/") + "/api/jd-wskey"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		autopostURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return jdWskeyExchangeResponse{Status: "error", Message: "构建 wskey exchange 请求失败"}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if a.cfg.AutopostToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.cfg.AutopostToken)
	}

	client := &http.Client{Timeout: jdWskeyTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[jdwskey-exchange] 请求失败: %v", err)
		return jdWskeyExchangeResponse{
			Status:  "error",
			Message: "jdback 服务连接失败: " + err.Error(),
		}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode != http.StatusOK {
		log.Printf("[jdwskey-exchange] HTTP %d: response body length=%d", resp.StatusCode, len(respBody))
		return jdWskeyExchangeResponse{
			Status:  "error",
			Message: fmt.Sprintf("jdback 返回 HTTP %d", resp.StatusCode),
		}, fmt.Errorf("jdback HTTP %d", resp.StatusCode)
	}

	var apResp jdWskeyExchangeResponse
	if err := json.Unmarshal(respBody, &apResp); err != nil {
		return jdWskeyExchangeResponse{
			Status:  "error",
			Message: "jdback 响应解析失败",
		}, err
	}

	return apResp, nil
}

// ── 兼容 jdcheck.go 中的 JD 结果展示 ──

// handleJdWskeyStatus returns the current wskey status for the account.
// GET /api/my/jd-wskey/status
func (a *App) handleJdWskeyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
	var acc *store.WechatAccount
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	adminCookie, _ := getCookie(r, "yyb_admin")
	if adminCookie != "" && a.webAuth.IsValidAdmin(adminCookie) && ref != "" {
		acc, err = a.db.ResolveAccount(r.Context(), ref)
	} else {
		acc, err = a.db.GetAccount(r.Context(), sess.WechatAccountID)
	}
	if err != nil || acc == nil {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}

	wskey, _ := a.db.GetJdWskey(r.Context(), acc.ID)
	hasWskey := wskey != ""

	jdCookie, err := a.db.GetJdCookie(r.Context(), acc.ID)
	hasCookie := err == nil && jdCookie != ""

	var pin, ptKey string
	if hasCookie {
		pin = parseCookieValue(jdCookie, "pt_pin")
		ptKey = parseCookieValue(jdCookie, "pt_key")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"openid":        acc.OpenID,
		"has_wskey":     hasWskey,
		"wskey_preview": maskWskey(wskey),
		"has_cookie":    hasCookie,
		"pt_pin":        pin,
		"pt_key":        truncateString(ptKey, 16),
	})
}

// maskWskey 只展示 wskey 前后各 6 个字符，中间用 *** 隐藏
func maskWskey(wskey string) string {
	if len(wskey) <= 16 {
		if len(wskey) <= 4 {
			return "***"
		}
		return wskey[:4] + "***"
	}
	return wskey[:6] + "***" + wskey[len(wskey)-6:]
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// escapeURLQuery 对 JD API 请求参数做 URL 编码，避免特殊字符导致签名或解析异常。
func escapeURLQuery(raw string) string {
	return url.QueryEscape(raw)
}
