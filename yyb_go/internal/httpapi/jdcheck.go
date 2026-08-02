package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"yyb_go/internal/store"
)

// ── JDCheckResult ──

// JDCheckResult is the JSON response for POST /api/my/jd-check.
type JDCheckResult struct {
	Status  string `json:"status"`             // "ok" | "risk" | "error"
	Message string `json:"message,omitempty"`   // human-readable summary
	RiskURL string `json:"risk_url,omitempty"`  // ACRJUrl if risk verification needed
	PTKey   string `json:"pt_key,omitempty"`    // pt_key if login succeeded
	Pin     string `json:"pt_pin,omitempty"`    // pt_pin if login succeeded
	Raw     string `json:"raw,omitempty"`       // truncated raw JD response for debugging
}

// ── Constants (aligned with JDCode.py) ──

const jdLoginTimeout = 15 * time.Second

// JD mini-program app_id (京东购物小程序) — from JDCode.py CONFIG_JD_APPID.
const jdAppID = "wx91d27dbf599dff74"

// JD login endpoint — login_lt, exactly as JDCode.py calls it.
const jdLoginLtURL = "https://wq.jd.com/mlogin/wxapp/login_lt"

// MicroMessenger User-Agent matching JDCode.py UA_WX.
const uaWx = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) " +
	"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 " +
	"MicroMessenger/8.0.49 NetType/WIFI Language/zh_CN miniProgram/" + jdAppID

// ── checkJDLogin ──

// checkJDLogin does the full flow:
//  1. Call yyb's pool.GetCode to get a wx mini-program code.
//  2. GET login_lt with the code and all required params.
//  3. Parse the response: if ACRJUrl → risk; if pt_key cookie → ok.
func (a *App) checkJDLogin(ctx context.Context, acc *store.WechatAccount) (JDCheckResult, error) {
	// Step 1: get mini-program code via yyb's existing pool.
	codeResult, err := a.pool.GetCode(ctx, acc.LoginBuffer, jdAppID, acc.ID, a.cfg.TCPProxy)
	if err != nil {
		return JDCheckResult{Status: "error", Message: "获取小程序 code 失败: " + err.Error()}, err
	}
	code, ok := codeResult["code"].(string)
	if !ok || code == "" {
		return JDCheckResult{Status: "error", Message: "小程序 code 为空"}, fmt.Errorf("empty code from GetCode")
	}

	// Step 2: GET login_lt with all required parameters (matching JDBC.py).
	jdResp, cookies, rawBody, err := callLoginLt(ctx, code)
	if err != nil {
		return JDCheckResult{Status: "error", Message: "京东登录请求失败: " + err.Error()}, err
	}

	// Truncate raw body for debugging.
	rawStr := rawBody
	if len(rawStr) > 800 {
		rawStr = rawStr[:800]
	}
	result := JDCheckResult{Raw: rawStr}

	// Step 3: Check for risk verification URL (ACRJUrl).
	// JD returns ACRJUrl in the "info" field or nested under "data".
	riskURL := extractACRJUrl(jdResp, rawBody)
	if riskURL != "" {
		result.Status = "risk"
		result.RiskURL = riskURL
		result.Message = "京东返回需二次验证，请点击下方链接完成认证后重新验证"
		_ = a.db.SetJdRiskURL(ctx, acc.ID, riskURL)
		return result, nil
	}

	// Step 4: Check for successful login via cookies (matching JDCode.py).
	for _, c := range cookies {
		if c.Name == "pt_key" && c.Value != "" {
			result.Status = "ok"
			result.PTKey = c.Value
			result.Message = "京东登录成功"
			for _, c2 := range cookies {
				if c2.Name == "pt_pin" || c2.Name == "pin" {
					result.Pin = c2.Value
				}
			}
			_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
			return result, nil
		}
	}

	// Neither risk URL nor pt_key cookie — unknown state.
	// Also check retCode / retMsg / msg / errmsg for error messages.
	errMsg := firstNonEmpty(
		strVal(jdResp, "retMsg"), strVal(jdResp, "retmsg"),
		strVal(jdResp, "msg"), strVal(jdResp, "message"),
		strVal(jdResp, "errmsg"), strVal(jdResp, "errMsg"),
	)
	result.Status = "error"
	if errMsg != "" {
		result.Message = "京东登录失败: " + errMsg
	} else {
		result.Message = "京东返回了未知响应，既没有 pt_key 也没有二次验证链接"
	}
	return result, fmt.Errorf("unknown JD response: retCode=%v retMsg=%s",
		jdResp["retCode"], errMsg)
}

// ── callLoginLt ──

// callLoginLt calls JD's login_lt endpoint as a GET with all required query
// parameters, matching JDBC.py's call_login_lt.
// Returns the parsed JSON payload (map), cookies, and raw body string.
func callLoginLt(ctx context.Context, code string) (map[string]any, []*http.Cookie, string, error) {
	ctx, cancel := context.WithTimeout(ctx, jdLoginTimeout)
	defer cancel()

	// Build query params matching JDCode.py call_login_lt.
	params := url.Values{}
	params.Set("appid", jdAppID)
	params.Set("code", code)
	params.Set("type", "silent")
	params.Set("isPopup", "false")
	params.Set("isIgnoreCookie", "false")
	params.Set("isOfficialPin", "false")
	params.Set("loginColor", "{}")
	params.Set("returnUrl", "pages/my/index/index")
	params.Set("deviceName", "iPhone")
	params.Set("deviceOS", "iOS")
	params.Set("deviceOSVersion", "17.0")
	params.Set("deviceVersion", "8.0.49")
	params.Set("g_tk", "0")
	params.Set("g_ty", "ls")

	reqURL := jdLoginLtURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, "", err
	}
	req.Header.Set("User-Agent", uaWx)
	req.Header.Set("Referer", "https://servicewechat.com/"+jdAppID+"/873/page-frame.html")
	req.Header.Set("Accept", "application/json,text/plain,*/*")

	// Use a cookie jar to properly capture Set-Cookie headers (pt_key, pt_pin).
	// Don't follow redirects — same behavior as JDCode.py's IncludedHandler.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: jdLoginTimeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, nil, "", err
	}
	rawBody := string(body)

	// Parse JSON body.
	var jdResp map[string]any
	_ = json.Unmarshal(body, &jdResp)

	// Get cookies from jar (for the JD domain) so pt_key/pt_pin from
	// across any redirect chain are visible.
	cookies := jar.Cookies(req.URL)
	if len(cookies) == 0 {
		// Fallback: direct Set-Cookie parse.
		cookies = resp.Cookies()
	}

	return jdResp, cookies, rawBody, nil
}

// ── extractACRJUrl ──

// extractACRJUrl locates the A / risk verification URL in a JD login_lt
// response, using the same strategy as JDCode.py's login_info +
// follow_server_refresh.
func extractACRJUrl(jdResp map[string]any, rawBody string) string {
	if jdResp == nil {
		return ""
	}

	// Strategy 1: response.info.ACBJUrl (when info is a JSON object).
	if info, ok := jdResp["info"]; ok {
		// info may be a parsed dict/map or a string.
		switch v := info.(type) {
		case map[string]any:
			if u := strVal(v, "ACRJUrl"); u != "" {
				return normaliseJDUrl(u)
			}
		case string:
			// Try to parse it as JSON.
			var m map[string]any
			if json.Unmarshal([]byte(v), &m) == nil {
				if u := strVal(m, "ACRJUrl"); u != "" {
					return normaliseJDUrl(u)
				}
			}
			// Maybe it's a direct URL.
			if strings.HasPrefix(v, "https://") && stringContains(v, "risk") {
				return normaliseJDUrl(v)
			}
		}
	}

	// Strategy 2: jdResp["data"]["info"]["ACRJUrl"].
	if data, ok := jdResp["data"].(map[string]any); ok {
		if info, ok := data["info"]; ok {
			if m, ok := info.(map[string]any); ok {
				if u := strVal(m, "ACRJUrl"); u != "" {
					return normaliseJDUrl(u)
				}
			}
		}
		// data["ACRJUrl"] directly.
		if u := strVal(data, "ACRJUrl"); u != "" {
			return normaliseJDUrl(u)
		}
	}

	// Fallback: full-text search in raw body for ACRNUrl pathern.
	return searchRawBodyForRiskUrl(rawBody)
}

// searchRawBodyForRiskUrl scans the raw body for a risk URL pathet.
func searchRawBodyForRiskUrl(rawBody string) string {
	// Pattern 1: "ACRJUrl":"https://..."
	idx := strings.Index(rawBody, `"ACRJUrl"`)
	if idx >= 0 {
		rest := rawBody[idx+len(`"ACRJUrl"`):]
		rest = trimLeadingColon(rest)
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end >= 0 {
				return normaliseJDUrl(rest[1 : 1+end])
			}
		}
	}

	// Pattern 2: Direct risk URL in body.
	riskPrefixes := []string{
		"https://wq.jd.com/h5/risk/",
		"https://plogin.m.jd.com/h5/risk/",
	}
	for _, prefix := range riskPrefixes {
		idx := strings.Index(rawBody, prefix)
		if idx < 0 {
			continue
		}
		rest := rawBody[idx:]
		for i, ch := range rest {
			if ch == '"' || ch == ' ' || ch == '\\' || ch == '\n' {
				return rest[:i]
			}
		}
		if len(rest) > 500 {
			return rest[:500]
		}
		return rest
	}

	return ""
}

func normaliseJDUrl(raw string) string {
	if strings.HasPrefix(raw, "//") {
		return "https:" + raw
	}
	if strings.HasPrefix(raw, "/") {
		return "https://wq.jd.com" + raw
	}
	return raw
}

// ── handleMyJdCheck ──

// handleMyJdCheck is the HTTP handler for POST /api/my/jd-check.
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

	result, err := a.checkJDLogin(r.Context(), acc)
	if err != nil && result.Status == "error" {
		writeJSON(w, http.StatusOK, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ── helpers ──

func strVal(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func stringContains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func trimLeadingColon(s string) string {
	return strings.TrimLeft(s, " \t\r\n:")
}
