package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"yyb_go/internal/store"
)

// ── JDCheckResult ──

type JDCheckResult struct {
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	RiskURL  string `json:"risk_url,omitempty"`
	PTKey    string `json:"pt_key,omitempty"`
	Pin      string `json:"pt_pin,omitempty"`
	JdCookie string `json:"jd_cookie,omitempty"`
	Raw      string `json:"raw,omitempty"`
}

const jdLoginTimeout = 15 * time.Second
const jdAppID = "wx91d27dbf599dff74"
const jdLoginLtURL = "https://wq.jd.com/mlogin/wxapp/login_lt"
const uaWx = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) " +
	"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 " +
	"MicroMessenger/8.0.49 NetType/WIFI Language/zh_CN miniProgram/" + jdAppID

// ── checkJDLogin ──

func (a *App) checkJDLogin(ctx context.Context, acc *store.WechatAccount) (JDCheckResult, error) {
	codeResult, err := a.pool.GetCode(ctx, acc.LoginBuffer, jdAppID, acc.ID, a.cfg.TCPProxy)
	if err != nil {
		return JDCheckResult{Status: "error", Message: "获取小程序 code 失败: " + err.Error()}, err
	}
	code, ok := codeResult["code"].(string)
	if !ok || code == "" {
		return JDCheckResult{Status: "error", Message: "小程序 code 为空"}, fmt.Errorf("empty code")
	}

	jdResp, cookies, rawBody, jar, _, err := callLoginLt(ctx, code)
	if err != nil {
		return JDCheckResult{Status: "error", Message: "京东登录请求失败: " + err.Error()}, err
	}

	rawStr := rawBody
	if len(rawStr) > 800 {
		rawStr = rawStr[:800]
	}
	result := JDCheckResult{Raw: rawStr}

	// Step 1: Check for risk verification URL.
	riskURL := extractACRJUrl(jdResp, rawBody)
	if riskURL != "" && isRiskURL(riskURL) {
		result.Status = "risk"
		result.RiskURL = riskURL
		result.Message = "京东返回需二次验证，请点击下方链接完成认证后重新验证"
		_ = a.db.SetJdRiskURL(ctx, acc.ID, riskURL)
		return result, nil
	}

	// Step 2: Check for pt_key in initial response cookies.
	ck := extractPtCookie(cookies)
	if ck != "" {
		result.Status = "ok"
		result.PTKey = cookieValue(cookies, "pt_key")
		result.Pin = cookieValue(cookies, "pt_pin", "pin")
		result.Message = "京东登录成功"
		result.JdCookie = ck
		_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
		return result, nil
	}

	// Step 3: Check response body JSON for pt_key/pt_pin.
	bodyCk := extractPtCookieFromBody(jdResp)
	if bodyCk != "" {
		result.Status = "ok"
		result.PTKey = parseCookieValue(bodyCk, "pt_key")
		result.Pin = parseCookieValue(bodyCk, "pt_pin")
		result.Message = "京东登录成功"
		result.JdCookie = bodyCk
		_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
		return result, nil
	}

	// Step 4: Follow server-side refresh redirect chain (matching JDCode.py).
	acrjURL := extractACRJUrl(jdResp, rawBody)
	acrjState := extractACRJState(jdResp, rawBody)
	if acrjURL != "" {
		refreshCk, err := followServerRefresh(ctx, acrjURL, acrjState, jar)
		if err == nil && refreshCk != "" {
			result.Status = "ok"
			result.PTKey = parseCookieValue(refreshCk, "pt_key")
			result.Pin = parseCookieValue(refreshCk, "pt_pin")
			result.Message = "京东登录成功"
			result.JdCookie = refreshCk
			_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
			return result, nil
		}
		// If follow failed and URL looks like risk, return as risk.
		if isRiskURL(acrjURL) {
			result.Status = "risk"
			result.RiskURL = acrjURL
			result.Message = "京东返回需二次验证，请点击下方链接完成认证后重新验证"
			_ = a.db.SetJdRiskURL(ctx, acc.ID, acrjURL)
			return result, nil
		}
	}

	// Step 5: Try sfsRefreshToken — JD often returns sfstoken+pin but no pt_key.
	// Need to call sfsRefreshToken to exchange sfstoken for pt_key (matching JDCode.py).
	sfsCk := sfsExchangePtKey(ctx, cookies, jar)
	if sfsCk != "" {
		result.Status = "ok"
		result.PTKey = parseCookieValue(sfsCk, "pt_key")
		result.Pin = parseCookieValue(sfsCk, "pt_pin")
		result.Message = "京东登录成功"
		result.JdCookie = sfsCk
		_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
		return result, nil
	}

	// Step 6: Check retMsg for SUCCESS — but only trust if we actually got CK.
	retMsg := firstNonEmpty(
		strVal(jdResp, "retMsg"), strVal(jdResp, "retmsg"),
		strVal(jdResp, "msg"), strVal(jdResp, "message"),
		strVal(jdResp, "errmsg"), strVal(jdResp, "errMsg"),
	)
	if strings.Contains(strings.ToUpper(retMsg), "SUCCESS") {
		// Don't fake success — if no CK was captured, report error.
		result.Status = "error"
		result.Message = "京东返回成功但未捕获到Cookie，请重新验证"
		return result, fmt.Errorf("SUCCESS but no pt_key/pt_pin captured")
	}

	result.Status = "error"
	if retMsg != "" {
		result.Message = "京东登录失败: " + retMsg
	} else {
		result.Message = "京东返回了未知响应"
	}
	return result, fmt.Errorf("unknown JD response: retCode=%v retMsg=%s", jdResp["retCode"], retMsg)
}

// ── callLoginLt ──

func callLoginLt(ctx context.Context, code string) (map[string]any, []*http.Cookie, string, *cookiejar.Jar, *url.URL, error) {
	ctx, cancel := context.WithTimeout(ctx, jdLoginTimeout)
	defer cancel()

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
		return nil, nil, "", nil, nil, err
	}
	req.Header.Set("User-Agent", uaWx)
	req.Header.Set("Referer", "https://servicewechat.com/"+jdAppID+"/873/page-frame.html")
	req.Header.Set("Accept", "application/json,text/plain,*/*")

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
		return nil, nil, "", nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, nil, "", nil, nil, err
	}
	rawBody := string(body)

	var jdResp map[string]any
	_ = json.Unmarshal(body, &jdResp)

	cookies := jar.Cookies(req.URL)
	cookies = append(cookies, resp.Cookies()...)

	return jdResp, cookies, rawBody, jar, resp.Request.URL, nil
}

// ── followServerRefresh ──

// followServerRefresh follows the JD server-side refresh redirect chain
// (matching JDCode.py's follow_server_refresh) to capture pt_key/pt_pin.
func followServerRefresh(ctx context.Context, acrjURL, acrjState string, jar *cookiejar.Jar) (string, error) {
	current := normaliseJDUrl(acrjURL)
	if current == "" {
		return "", fmt.Errorf("empty ACRJUrl")
	}

	if acrjState != "" && !strings.Contains(current, "ACRJState=") {
		parsed, err := url.Parse(current)
		if err == nil {
			q := parsed.Query()
			q.Set("ACRJState", acrjState)
			parsed.RawQuery = q.Encode()
			current = parsed.String()
		}
	}

	client := &http.Client{
		Timeout: jdLoginTimeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for i := 0; i < 8; i++ {
		if !allowedJDURL(current) {
			return "", fmt.Errorf("server refresh URL not trusted: %s", current)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", uaWx)
		req.Header.Set("Referer", "https://servicewechat.com/"+jdAppID+"/873/page-frame.html")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}

		// Check jar + response Set-Cookie.
		allCk := jar.Cookies(req.URL)
		allCk = append(allCk, resp.Cookies()...)
		ck := extractPtCookie(allCk)
		if ck != "" {
			resp.Body.Close()
			return ck, nil
		}

		// Check response body for pt_key/pt_pin.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()

		var bodyJSON map[string]any
		if json.Unmarshal(body, &bodyJSON) == nil {
			bodyCk := extractPtCookieFromBody(bodyJSON)
			if bodyCk != "" {
				return bodyCk, nil
			}
		}

		// Check raw body for cookie pattern.
		rawCk := parseCookieFromRaw(string(body))
		if rawCk != "" {
			return rawCk, nil
		}

		// Follow redirect.
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}
		current = resolveURL(current, location)
		time.Sleep(200 * time.Millisecond)
	}

	return "", fmt.Errorf("follow_server_refresh: no pt_key/pt_pin after 8 hops")
}

// ── sfsExchangePtKey ──

// sfsExchangePtKey calls JD's sfsRefreshToken endpoint to exchange sfstoken
// for pt_key, matching JDCode.py's sfs_exchange_pt_key.
// JD often returns sfstoken+pin cookies but no pt_key; this extra call is needed.
const jdSfsRefreshURL = "https://wq.jd.com/mlogin/wxapp/sfsRefreshToken"

func sfsExchangePtKey(ctx context.Context, cookies []*http.Cookie, jar *cookiejar.Jar) string {
	sfs := cookieValue(cookies, "sfstoken")
	pin := cookieValue(cookies, "pin", "pt_pin")
	if sfs == "" || pin == "" {
		return ""
	}

	ctx2, cancel := context.WithTimeout(ctx, jdLoginTimeout)
	defer cancel()

	params := url.Values{}
	params.Set("appid", jdAppID)
	params.Set("pin", pin)
	params.Set("sfstoken", sfs)
	params.Set("type", "silent")
	params.Set("isPopup", "false")
	params.Set("isIgnoreCookie", "false")
	params.Set("g_tk", "0")
	params.Set("g_ty", "ls")

	reqURL := jdSfsRefreshURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx2, http.MethodGet, reqURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", uaWx)
	req.Header.Set("Referer", "https://servicewechat.com/"+jdAppID+"/873/page-frame.html")
	req.Header.Set("Accept", "application/json,text/plain,*/*")

	client := &http.Client{
		Timeout: jdLoginTimeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	// 1. Check jar + response Set-Cookie.
	allCk := jar.Cookies(req.URL)
	allCk = append(allCk, resp.Cookies()...)
	ck := extractPtCookie(allCk)
	if ck != "" {
		return ck
	}

	// 2. Check response body JSON for pt_key/pt_pin.
	var sfsResp map[string]any
	if json.Unmarshal(body, &sfsResp) == nil {
		bodyCk := extractPtCookieFromBody(sfsResp)
		if bodyCk != "" {
			return bodyCk
		}
		// 3. Check raw body for cookie pattern.
		rawCk := parseCookieFromRaw(string(body))
		if rawCk != "" {
			return rawCk
		}
		// 4. SFS response may contain a new ACRJUrl — follow it.
		acrjURL := extractACRJUrl(sfsResp, string(body))
		acrjState := extractACRJState(sfsResp, string(body))
		if acrjURL != "" {
			refreshCk, err := followServerRefresh(ctx, acrjURL, acrjState, jar)
			if err == nil && refreshCk != "" {
				return refreshCk
			}
		}
	}

	// 5. Fallback: check raw body.
	rawCk := parseCookieFromRaw(string(body))
	if rawCk != "" {
		return rawCk
	}

	return ""
}

// ── cookie helpers ──

func extractPtCookie(cookies []*http.Cookie) string {
	var ptKey, ptPin string
	for _, c := range cookies {
		switch c.Name {
		case "pt_key":
			if c.Value != "" {
				ptKey = c.Value
			}
		case "pt_pin", "pin":
			if c.Value != "" && ptPin == "" {
				ptPin = c.Value
			}
		}
	}
	if ptKey == "" || ptPin == "" {
		return ""
	}
	return "pt_key=" + ptKey + ";pt_pin=" + ptPin + ";"
}

func cookieValue(cookies []*http.Cookie, names ...string) string {
	for _, name := range names {
		for _, c := range cookies {
			if c.Name == name && c.Value != "" {
				return c.Value
			}
		}
	}
	return ""
}

func parseCookieValue(cookieStr, key string) string {
	prefix := key + "="
	for _, part := range strings.Split(cookieStr, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return ""
}

func extractPtCookieFromBody(m map[string]any) string {
	if m == nil {
		return ""
	}
	ptKey := strVal(m, "pt_key")
	ptPin := strVal(m, "pt_pin")
	if ptKey == "" {
		if info, ok := m["info"].(map[string]any); ok {
			ptKey = strVal(info, "pt_key")
			ptPin = strVal(info, "pt_pin")
		}
	}
	if ptKey == "" {
		if data, ok := m["data"].(map[string]any); ok {
			ptKey = strVal(data, "pt_key")
			ptPin = strVal(data, "pt_pin")
		}
	}
	if ptKey != "" && ptPin != "" {
		return "pt_key=" + ptKey + ";pt_pin=" + ptPin + ";"
	}
	return ""
}

func parseCookieFromRaw(raw string) string {
	ptKey := extractRawValue(raw, "pt_key=")
	ptPin := extractRawValue(raw, "pt_pin=")
	if ptKey != "" && ptPin != "" {
		return "pt_key=" + ptKey + ";pt_pin=" + ptPin + ";"
	}
	return ""
}

func extractRawValue(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	end := len(rest)
	for i, ch := range rest {
		if ch == ';' || ch == ',' || ch == ' ' || ch == '"' || ch == ')' || ch == '\n' || ch == '\r' {
			end = i
			break
		}
	}
	return rest[:end]
}

// ── URL helpers ──

func allowedJDURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "https" {
		return false
	}
	return host == "jd.com" || strings.HasSuffix(host, ".jd.com") ||
		host == "jd.hk" || strings.HasSuffix(host, ".jd.hk") ||
		host == "3.cn" || strings.HasSuffix(host, ".3.cn")
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "//") {
		return "https:" + ref
	}
	if strings.HasPrefix(ref, "/") {
		parsed, err := url.Parse(base)
		if err == nil {
			return parsed.Scheme + "://" + parsed.Host + ref
		}
	}
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return ref
	}
	baseParsed, err := url.Parse(base)
	if err == nil {
		resolved := baseParsed.ResolveReference(&url.URL{Path: ref})
		return resolved.String()
	}
	return ref
}

func isRiskURL(rawURL string) bool {
	return strings.Contains(rawURL, "/risk/") ||
		strings.Contains(rawURL, "risk") ||
		strings.Contains(rawURL, "verify")
}

// ── ACRJUrl extraction ──

func extractACRJUrl(jdResp map[string]any, rawBody string) string {
	if jdResp == nil {
		return ""
	}
	if info, ok := jdResp["info"]; ok {
		switch v := info.(type) {
		case map[string]any:
			if u := strVal(v, "ACRJUrl"); u != "" {
				return normaliseJDUrl(u)
			}
		case string:
			var m map[string]any
			if json.Unmarshal([]byte(v), &m) == nil {
				if u := strVal(m, "ACRJUrl"); u != "" {
					return normaliseJDUrl(u)
				}
			}
			if strings.HasPrefix(v, "https://") && stringContains(v, "risk") {
				return normaliseJDUrl(v)
			}
		}
	}
	if data, ok := jdResp["data"].(map[string]any); ok {
		if info, ok := data["info"]; ok {
			if m, ok := info.(map[string]any); ok {
				if u := strVal(m, "ACRJUrl"); u != "" {
					return normaliseJDUrl(u)
				}
			}
		}
		if u := strVal(data, "ACRJUrl"); u != "" {
			return normaliseJDUrl(u)
		}
	}
	return searchRawBodyForRiskUrl(rawBody)
}

func extractACRJState(jdResp map[string]any, rawBody string) string {
	if jdResp == nil {
		return ""
	}
	if info, ok := jdResp["info"].(map[string]any); ok {
		if s := strVal(info, "ACRJState"); s != "" {
			return s
		}
	}
	if data, ok := jdResp["data"].(map[string]any); ok {
		if info, ok := data["info"].(map[string]any); ok {
			if s := strVal(info, "ACRJState"); s != "" {
				return s
			}
		}
	}
	idx := strings.Index(rawBody, `"ACRJState"`)
	if idx >= 0 {
		rest := rawBody[idx+len(`"ACRJState"`):]
		rest = trimLeadingColon(rest)
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end >= 0 {
				return rest[1 : 1+end]
			}
		}
	}
	return ""
}

func searchRawBodyForRiskUrl(rawBody string) string {
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
		a.pushWxNotification(acc.ID, "jd_check", result.Message)
		writeJSON(w, http.StatusOK, result)
		return
	}
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

func (a *App) pushWxNotification(accountID int64, msgType, content string) {
	if content == "" {
		return
	}
	_, err := a.db.PushWxMessage(context.Background(), accountID, msgType, content)
	if err != nil {
		log.Printf("[wx-push] failed to push wx message for account %d: %v", accountID, err)
	}
}
