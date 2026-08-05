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
	"regexp"
	"strings"
	"time"

	"yyb_go/internal/store"
)

// ── JDCheckResult ──

type JDCheckResult struct {
	Status       string `json:"status"`
	Message      string `json:"message,omitempty"`
	RiskURL      string `json:"risk_url,omitempty"`
	RiskExpireAt int64  `json:"risk_expire_at,omitempty"`
	PTKey        string `json:"pt_key,omitempty"`
	Pin          string `json:"pt_pin,omitempty"`
	JdCookie     string `json:"jd_cookie,omitempty"`
	Raw          string `json:"raw,omitempty"`
}

// 超时常量：login_lt 用 20s，PT exchange 用独立 30s（对应 JDCode.py 的 30s 超时）。
const jdLoginTimeout = 20 * time.Second
const jdPTTimeout = 30 * time.Second
const jdAppID = "wx91d27dbf599dff74"
const jdLoginLtURL = "https://wq.jd.com/mlogin/wxapp/login_lt"

// riskURLTTL 是京东风险验证链接的前端失效时间。
// 京东不返回明确的 expire 字段，按行业惯例设置 30 分钟。
const riskURLTTL = 30 * time.Minute
const uaWx = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) " +
	"AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 " +
	"MicroMessenger/8.0.49 NetType/WIFI Language/zh_CN miniProgram/" + jdAppID

// PT OAuth constants (matching JDCode.py jd_pt_cookie_login).
const jdPTAppID = "wx2f5d8f9715c59d10"
const jdPTApp = "300"
const jdPTReturnURL = "https://my.m.jd.com/account/index.html"
const uaPT = "Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 " +
	"Mobile Safari/537.36 MicroMessenger/7.0.20.1781 " +
	"NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF"

// ── checkJDLogin ──

func (a *App) checkJDLogin(ctx context.Context, acc *store.WechatAccount) (JDCheckResult, error) {
	// ── Phase 1: code-only attempt (matching JDCode.py attempt_code_login(full=false)) ──

	codeResult, err := a.pool.GetCode(ctx, acc.LoginBuffer, jdAppID, acc.ID, a.cfg.TCPProxy)
	if err != nil {
		// session 可能过期了，失效旧的 + 刷新账号 + 重试一次
		_ = a.pool.Invalidate(ctx, acc.ID, a.cfg.TCPProxy)
		if a.refreshLiveness(ctx, acc) == "alive" {
			if fresh, e := a.db.GetAccount(ctx, acc.ID); e == nil && fresh != nil {
				acc = fresh
			}
			codeResult, err = a.pool.GetCode(ctx, acc.LoginBuffer, jdAppID, acc.ID, a.cfg.TCPProxy)
		}
		if err != nil {
			return JDCheckResult{Status: "error", Message: "获取小程序 code 失败: " + err.Error()}, err
		}
	}

	code, ok := codeResult["code"].(string)
	if !ok || code == "" {
		return JDCheckResult{Status: "error", Message: "小程序 code 为空"}, fmt.Errorf("empty code")
	}

	jdResp, cookies, rawBody, jar, _, err := callLoginLt(ctx, code, nil)
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
	acrjState := extractACRJState(jdResp, rawBody)
	riskFlwType := extractRiskFlwType(jdResp, rawBody)

	if riskURL != "" {
		log.Printf(
			"[JD风险认证] ACRJUrl=%s ACRJState=%s RiskFlwType=%d",
			riskURL,
			acrjState,
			riskFlwType,
		)
	}

	if riskURL != "" && isRealRiskURL(riskURL) {
		result.Status = "risk"
		result.RiskURL = riskURL
		result.RiskExpireAt = time.Now().Add(riskURLTTL).Unix()
		result.Message = "京东返回需二次验证，请点击下方链接完成认证后重新验证"
		_ = a.db.SetJdRiskURLWithExpiry(ctx, acc.ID, riskURL, riskURLTTL)
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
		// If follow failed and URL is a real risk URL, return as risk.
		if isRealRiskURL(acrjURL) {
			result.Status = "risk"
			result.RiskURL = acrjURL
			result.RiskExpireAt = time.Now().Add(riskURLTTL).Unix()
			result.Message = "京东返回需二次验证，请点击下方链接完成认证后重新验证"
			_ = a.db.SetJdRiskURLWithExpiry(ctx, acc.ID, acrjURL, riskURLTTL)
			return result, nil
		}
	}

	// Step 5: Try sfsRefreshToken — JD often returns sfstoken+pin but no pt_key.
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

	// Step 5.5: PT exchange — use PT appid to get a fresh code, then walk the PT OAuth chain.
	// 用独立 context 避免 deadline propagation（前面步骤已消耗部分时间）。
	ptCtx, ptCancel := context.WithTimeout(context.Background(), jdPTTimeout)
	defer ptCancel()

	ptCode, ptErr := a.pool.GetCode(ptCtx, acc.LoginBuffer, jdPTAppID, acc.ID, a.cfg.TCPProxy)
	if ptErr == nil && ptCode != nil {
		if ptCodeVal, ok := ptCode["code"].(string); ok && ptCodeVal != "" {
			ptCk := jdPtCookieLogin(ptCtx, ptCodeVal)
			if ptCk != "" {
				result.Status = "ok"
				result.PTKey = parseCookieValue(ptCk, "pt_key")
				result.Pin = parseCookieValue(ptCk, "pt_pin")
				result.Message = "京东登录成功"
				result.JdCookie = ptCk
				_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
				return result, nil
			}
		}
	}

	// ── Phase 2: full mode fallback (matching JDCode.py attempt_code_login(full=true)) ──
	// code-only 全部失败后，获取 getUserInfo 并带完整参数重试 login_lt。
	// 这对应 JDCode.py auto 模式：code-only 失败 → full mode 重试。

	userInfo, uiErr := a.getUserInfo(ctx, acc)
	if uiErr == nil && userInfo != nil {
		// 取新 code（不复用旧 code）。
		fullCodeResult, fcErr := a.pool.GetCode(ctx, acc.LoginBuffer, jdAppID, acc.ID, a.cfg.TCPProxy)
		if fcErr == nil {
			if fullCode, ok := fullCodeResult["code"].(string); ok && fullCode != "" {
				fullResp, fullCookies, fullRaw, fullJar, _, flErr := callLoginLt(ctx, fullCode, userInfo)
				if flErr == nil {
					// 重复 Step 1-5 with full params。
					fullCk := tryExtractCookie(fullResp, fullCookies, fullRaw, fullJar, ctx, acc)
					if fullCk != "" {
						result.Status = "ok"
						result.PTKey = parseCookieValue(fullCk, "pt_key")
						result.Pin = parseCookieValue(fullCk, "pt_pin")
						result.Message = "京东登录成功（full mode）"
						result.JdCookie = fullCk
						_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
						return result, nil
					}

					// full mode 也走 PT exchange。
					ptCtx2, ptCancel2 := context.WithTimeout(context.Background(), jdPTTimeout)
					defer ptCancel2()

					ptCode2, ptErr2 := a.pool.GetCode(ptCtx2, acc.LoginBuffer, jdPTAppID, acc.ID, a.cfg.TCPProxy)
					if ptErr2 == nil && ptCode2 != nil {
						if ptCodeVal2, ok := ptCode2["code"].(string); ok && ptCodeVal2 != "" {
							ptCk2 := jdPtCookieLogin(ptCtx2, ptCodeVal2)
							if ptCk2 != "" {
								result.Status = "ok"
								result.PTKey = parseCookieValue(ptCk2, "pt_key")
								result.Pin = parseCookieValue(ptCk2, "pt_pin")
								result.Message = "京东登录成功（full mode + PT exchange）"
								result.JdCookie = ptCk2
								_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
								return result, nil
							}
						}
					}
				}
			}
		}
	}

	// Step 6: Check retMsg for SUCCESS — but only trust if we actually got CK.
	retMsg := firstNonEmpty(
		strVal(jdResp, "retMsg"), strVal(jdResp, "retmsg"),
		strVal(jdResp, "msg"), strVal(jdResp, "message"),
		strVal(jdResp, "errmsg"), strVal(jdResp, "errMsg"),
	)
	if strings.Contains(strings.ToUpper(retMsg), "SUCCESS") {
		riskURL := extractACRJUrl(jdResp, rawBody)
		if riskURL != "" && isRealRiskURL(riskURL) {
			result.Status = "risk"
			result.RiskURL = riskURL
			result.RiskExpireAt =
				time.Now().Add(riskURLTTL).Unix()
			result.Message =
				"京东需要安全验证，请完成认证后重新验证"
			_ = a.db.SetJdRiskURLWithExpiry(
				ctx,
				acc.ID,
				riskURL,
				riskURLTTL,
			)
			return result, nil
		}

		result.Status = "error"
		result.Message =
			"京东返回成功但未捕获到Cookie，请重新验证"
		return result, fmt.Errorf(
			"SUCCESS but no pt_key/pt_pin captured",
		)
	}

	result.Status = "error"
	if retMsg != "" {
		result.Message = "京东登录失败: " + retMsg
	} else {
		result.Message = "京东返回了未知响应"
	}
	return result, fmt.Errorf("unknown JD response: retCode=%v retMsg=%s", jdResp["retCode"], retMsg)
}

// ── tryExtractCookie runs Steps 1-5 on a given login_lt response, returning
// the first pt_key/pt_pin cookie found, or "" if all steps fail. ──

func tryExtractCookie(jdResp map[string]any, cookies []*http.Cookie, rawBody string, jar *cookiejar.Jar, ctx context.Context, acc *store.WechatAccount) string {
	// Step 1: risk check
	riskURL := extractACRJUrl(jdResp, rawBody)
	if riskURL != "" && isRealRiskURL(riskURL) {
		return ""
	}

	// Step 2: cookie jar
	ck := extractPtCookie(cookies)
	if ck != "" {
		return ck
	}

	// Step 3: response body
	bodyCk := extractPtCookieFromBody(jdResp)
	if bodyCk != "" {
		return bodyCk
	}

	// Step 4: ACRJUrl refresh chain
	acrjURL := extractACRJUrl(jdResp, rawBody)
	acrjState := extractACRJState(jdResp, rawBody)
	if acrjURL != "" {
		refreshCk, err := followServerRefresh(ctx, acrjURL, acrjState, jar)
		if err == nil && refreshCk != "" {
			return refreshCk
		}
	}

	// Step 5: sfsRefreshToken
	sfsCk := sfsExchangePtKey(ctx, cookies, jar)
	if sfsCk != "" {
		return sfsCk
	}

	return ""
}

// ── getUserInfo (matching JDCode.py get_yyb_user_info) ──

// userInfo payload for login_lt with full credentials.
type jdUserInfo struct {
	RawData     string `json:"rawData"`
	Signature   string `json:"signature"`
	EncrytData  string `json:"encrytData"`
	IV          string `json:"iv"`
	OpenID      string `json:"openid"`
}

func (a *App) getUserInfo(ctx context.Context, acc *store.WechatAccount) (*jdUserInfo, error) {
	// 调用 pool.OperateWXData 获取 getUserInfo（对应 JDCode.py get_yyb_user_info → operateWxData）。
	payload := map[string]any{
		"api_name": "getUserInfo",
		"data":     map[string]any{"withCredentials": true},
		"env":      1,
	}

	resp, err := a.pool.OperateWXData(ctx, acc.LoginBuffer, jdAppID, payload, acc.ID, a.cfg.TCPProxy)
	if err != nil {
		return nil, err
	}

	result := unwrapOperateResponse(resp)

	// Extract rawData — rebuild from userInfo if not directly present.
	rawData := strVal(result, "rawData")
	if rawData == "" {
		rawData = strVal(result, "raw_data")
	}
	if rawData == "" {
		// 重建 rawData from userInfo fields (matching JDCode.py logic).
		userInfoMap := extractUserInfoMap(result)
		if len(userInfoMap) > 0 {
			rawDataBytes, _ := json.Marshal(userInfoMap)
			rawData = string(rawDataBytes)
		}
	}

	encrypted := firstNonEmpty(
		strVal(result, "encryptedData"),
		strVal(result, "encrytData"),
		strVal(result, "encrypted_data"),
		strVal(result, "encrypteddata"),
	)
	signature := strVal(result, "signature")
	iv := strVal(result, "iv")
	openid := firstNonEmpty(
		strVal(result, "openid"),
		strVal(result, "openId"),
		strVal(result, "open_id"),
	)

	if rawData == "" || signature == "" || encrypted == "" || iv == "" {
		return nil, fmt.Errorf("getUserInfo missing fields: rawData=%v signature=%v encrypted=%v iv=%v",
			rawData != "", signature != "", encrypted != "", iv != "")
	}

	return &jdUserInfo{
		RawData:    rawData,
		Signature:  signature,
		EncrytData: encrypted,
		IV:         iv,
		OpenID:     openid,
	}, nil
}

// unwrapOperateResponse extracts the data payload from OperateWXData response.
func unwrapOperateResponse(resp map[string]any) map[string]any {
	if resp == nil {
		return map[string]any{}
	}
	// OperateWXData returns parsed response directly.
	// Some versions wrap in {code, data, msg}.
	if data, ok := resp["data"].(map[string]any); ok {
		if inner, ok := data["data"].(map[string]any); ok {
			return inner
		}
		return data
	}
	return resp
}

// extractUserInfoMap builds a userInfo map from scattered fields (matching JDCode.py fallback).
func extractUserInfoMap(result map[string]any) map[string]any {
	// Try nested userInfo first.
	if ui, ok := result["userInfo"].(map[string]any); ok {
		return ui
	}
	if ui, ok := result["user_info"].(map[string]any); ok {
		return ui
	}
	// Fallback: collect standard keys from root.
	keys := []string{"nickName", "gender", "language", "city", "province", "country", "avatarUrl"}
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := result[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// ── callLoginLt ──

// callLoginLt now accepts optional userInfo for full-mode login (matching JDCode.py).
func callLoginLt(ctx context.Context, code string, userInfo *jdUserInfo) (map[string]any, []*http.Cookie, string, *cookiejar.Jar, *url.URL, error) {
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

	// Full mode: append userInfo params (matching JDCode.py call_login_lt with user_info).
	if userInfo != nil {
		params.Set("rawData", userInfo.RawData)
		params.Set("signature", userInfo.Signature)
		params.Set("encrytData", userInfo.EncrytData)
		params.Set("encryptedData", userInfo.EncrytData)
		params.Set("iv", userInfo.IV)
		params.Set("ou", userInfo.OpenID)
	}

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

// isRealRiskURL 判断一个 URL 是否是真正的京东风险验证链接。
// 真正的风险验证链接形如：
//   https://plogin.m.jd.com/h5/risk/select?token=...&client_type=wxapp&guid=...&appid=...&type=wq
// 排除的是 wqs.jd.com/downloadApp/download.html 这类下载引导页。
func isRealRiskURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	path := strings.ToLower(parsed.Path)

	// 必须是 jd.com 域名
	if !strings.HasSuffix(host, "jd.com") {
		return false
	}

	// 路径必须包含 /risk/
	if !strings.Contains(path, "/risk/") {
		return false
	}

	// 必须有 token 参数才算有效的风险验证链接
	q := parsed.Query()
	if q.Get("token") == "" {
		return false
	}

	return true
}

// isRiskURL is the old broad matcher, kept for backward compatibility in
// cases where we want to check if a URL is risk-related (even without token).
// Compared to the original, it now excludes downloadApp/download.html URLs
// and enforces jd.com domain check.
func isRiskURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	path := strings.ToLower(parsed.Path)

	// Exclude downloadApp / download.html — these are NOT risk URLs.
	if strings.Contains(path, "downloadapp") || strings.Contains(path, "download.html") {
		return false
	}

	// Only accept jd.com domains.
	if !strings.HasSuffix(host, "jd.com") {
		return false
	}

	return strings.Contains(path, "/risk/") ||
		strings.Contains(path, "verify")
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

func extractRiskFlwType(resp map[string]any, raw string) int {
	if info, ok := resp["info"].(map[string]any); ok {
		switch v := info["RiskFlwType"].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}

	// 兜底：正则匹配
	re := regexp.MustCompile(`"RiskFlwType"\s*:\s*(\d+)`)
	m := re.FindStringSubmatch(raw)

	if len(m) == 2 {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		return n
	}
	return 0
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

// ── jdPtCookieLogin (Step 5.5: PT OAuth chain) ──

// jdPtCookieLogin walks the JD PT OAuth redirect chain (matching JDCode.py
// jd_pt_cookie_login) to capture pt_key/pt_pin cookies.
func jdPtCookieLogin(ctx context.Context, code string) string {
	ctx2, cancel := context.WithTimeout(ctx, jdPTTimeout)
	defer cancel()

	jdPtHeaders := map[string]string{
		"User-Agent":      uaPT,
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9",
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: jdPTTimeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Hit login.action to get the OAuth redirect.
	loginParams := url.Values{}
	loginParams.Set("appid", jdPTApp)
	loginParams.Set("returnurl", jdPTReturnURL)
	loginURL := "https://plogin.m.jd.com/user/login.action?" + loginParams.Encode()

	req, err := http.NewRequestWithContext(ctx2, http.MethodGet, loginURL, nil)
	if err != nil {
		return ""
	}
	for k, v := range jdPtHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return ""
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return ""
	}

	oauthURL := resolveURL(loginURL, location)
	oauthParsed, err := url.Parse(oauthURL)
	if err != nil {
		return ""
	}
	oauthQuery := oauthParsed.Query()
	if oauthQuery.Get("appid") != jdPTAppID {
		return ""
	}
	redirectURI := oauthQuery.Get("redirect_uri")
	state := oauthQuery.Get("state")
	if redirectURI == "" || state == "" {
		return ""
	}

	// 2. Build callback URL with code+state appended.
	callbackParsed, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	callbackQuery := callbackParsed.Query()
	if callbackQuery == nil {
		callbackQuery = url.Values{}
	}
	callbackQuery.Set("code", code)
	callbackQuery.Set("state", state)
	callbackParsed.RawQuery = callbackQuery.Encode()
	current := callbackParsed.String()

	// 3. Walk the redirect chain (up to 8 hops).
	for i := 0; i < 8; i++ {
		if !allowedJDURL(current) {
			return ""
		}

		req, err := http.NewRequestWithContext(ctx2, http.MethodGet, current, nil)
		if err != nil {
			return ""
		}
		for k, v := range jdPtHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return ""
		}

		// Check jar + response Set-Cookie.
		allCk := jar.Cookies(req.URL)
		allCk = append(allCk, resp.Cookies()...)
		ck := extractPtCookie(allCk)
		if ck != "" {
			resp.Body.Close()
			return ck
		}

		// Read body for fallback checks.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		rawBody := string(body)

		// Check raw body for cookie pattern.
		rawCk := parseCookieFromRaw(rawBody)
		if rawCk != "" {
			return rawCk
		}

		// Check body JSON.
		var bodyJSON map[string]any
		if json.Unmarshal(body, &bodyJSON) == nil {
			bodyCk := extractPtCookieFromBody(bodyJSON)
			if bodyCk != "" {
				return bodyCk
			}
		}

		// Follow redirect.
		loc := resp.Header.Get("Location")
		statusCode := resp.StatusCode

		// If no Location header but 200, try HTML meta/JS redirect.
		if loc == "" && statusCode == 200 {
			loc = jdPtHTMLRedirect(current, rawBody)
		}

		if loc == "" || statusCode < 200 || statusCode > 399 {
			break
		}

		current = resolveURL(current, loc)
	}

	return ""
}

// jdPtHTMLRedirect extracts a redirect URL from HTML meta refresh or JS location
// assignments (matching JDCode.py jd_pt_html_redirect).
var ptRedirectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<meta[^>]+url\s*=\s*["']?([^"' >]+)`),
	regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)`),
	regexp.MustCompile(`(?i)location\.replace\s*\(\s*["']([^"']+)`),
	regexp.MustCompile(`(?i)location\.assign\s*\(\s*["']([^"']+)`),
}

func jdPtHTMLRedirect(baseURL, raw string) string {
	for _, pat := range ptRedirectPatterns {
		m := pat.FindStringSubmatch(raw)
		if m != nil {
			candidate := strings.TrimSpace(m[1])
			if candidate != "" {
				return resolveURL(baseURL, candidate)
			}
		}
	}
	return ""
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
