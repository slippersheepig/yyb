package protocol

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	yybHost         = "https://yybadaccess.3g.qq.com"
	loginBufferURL  = yybHost + "/pc_yyb_auth/pcyyb_get_wx_login_buffer_auth"
	refreshTokenURL = yybHost + "/pc_yyb_auth/pcyyb_refresh_token_auth"
	mainRefreshURL  = yybHost + "/pc_yyb/pcyyb_refresh_token"
	checkLoginURL   = yybHost + "/pc_yyb/pcyyb_check_login"
	userInfoURL     = yybHost + "/pc_yyb/pcyyb_get_user_info"
	mainBusinessID  = "pc_yyb"
	loginBusinessID = "pc_yyb_auth"
	loginAccessKey  = "wgrdg373hy26ww2"
)

type RefreshRejectedError struct {
	Code      int
	Message   string
	Operation string
}

func (e *RefreshRejectedError) Error() string {
	op := e.Operation
	if op == "" {
		op = "refresh"
	}
	return fmt.Sprintf("%s failed: code=%d msg=%s", op, e.Code, e.Message)
}

type LoginBufferRejectedError struct {
	Code    int
	Message string
}

func (e *LoginBufferRejectedError) Error() string {
	return fmt.Sprintf("login_buffer failed: code=%d msg=%s", e.Code, e.Message)
}

// IsHardCredentialRevoked reports whether an upstream refresh/check_login error
// indicates explicit WeChat refresh_token revocation (42007 / 40030 / 42002 / 40188).
func IsHardCredentialRevoked(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "42007") ||
		strings.Contains(s, "40030") ||
		strings.Contains(s, "42002") ||
		strings.Contains(s, "40188") ||
		strings.Contains(s, "invalid refresh_token")
}

type LoginBufferCredentials struct {
	OpenID            string `json:"openid"`
	AccessToken       string `json:"accesstoken"`
	RefreshToken      string `json:"refreshtoken"`
	RefreshBusinessID string `json:"refresh_business_id,omitempty"`
	LoginType         string `json:"logintype"`
	Nickname          string `json:"nickname"`
	ExpiresAt         int64  `json:"expires_at"`
	ExpiresIn         int64  `json:"expires_in"`
}

func CredentialsFromMap(m map[string]any) LoginBufferCredentials {
	expiresIn := defaultInt64(int64FromMap(m, "expires_in"), 7200)
	expiresAt := int64FromMap(m, "expires_at")
	if expiresAt <= 0 {
		if refreshedAt := int64FromMap(m, "refresh_refreshed_at"); refreshedAt > 0 {
			expiresAt = refreshedAt + expiresIn
		}
	}
	return LoginBufferCredentials{
		OpenID:            stringFromMap(m, "openid"),
		AccessToken:       stringFromMap(m, "accesstoken"),
		RefreshToken:      stringFromMap(m, "refreshtoken"),
		RefreshBusinessID: stringFromMap(m, "refresh_business_id"),
		LoginType:         defaultString(stringFromMap(m, "logintype"), "WX"),
		Nickname:          stringFromMap(m, "nickname"),
		ExpiresAt:         expiresAt,
		ExpiresIn:         expiresIn,
	}
}

func (c LoginBufferCredentials) ToMap() map[string]any {
	return map[string]any{
		"openid":               c.OpenID,
		"accesstoken":          c.AccessToken,
		"refreshtoken":         c.RefreshToken,
		"refresh_business_id":  c.RefreshBusinessID,
		"logintype":            defaultString(c.LoginType, "WX"),
		"nickname":             c.Nickname,
		"expires_at":           c.ExpiresAt,
		"expires_in":           defaultInt64(c.ExpiresIn, 7200),
		"refresh_refreshed_at": time.Now().Unix(),
	}
}

func (c LoginBufferCredentials) Expired(skew time.Duration) bool {
	return time.Now().Add(skew).Unix() >= c.ExpiresAt
}

type LoginBufferResult struct {
	LoginBuffer string
	Credentials LoginBufferCredentials
	Refreshed   bool
}

type LoginBufferClient struct {
	httpClient *http.Client
	timeout    time.Duration
}

func NewLoginBufferClient(timeout time.Duration) *LoginBufferClient {
	return &LoginBufferClient{
		httpClient: &http.Client{Timeout: timeout},
		timeout:    timeout,
	}
}

func (c *LoginBufferClient) FetchLoginBuffer(ctx context.Context, creds LoginBufferCredentials) (string, error) {
	body, err := json.Marshal(loginBufferRequest{
		ExtInfo: loginExtInfo{
			ListS: loginListS{
				UnionID:     loginValueString{Value: []string{creds.OpenID}},
				UserID:      loginValueString{Value: []string{creds.OpenID}},
				AccessToken: loginValueString{Value: []string{creds.AccessToken}},
			},
			ListI: loginListI{UserType: loginValueInt{Value: []int{0}}},
		},
	})
	if err != nil {
		return "", err
	}
	ts, nonce := timestampMS(), nonce4()
	var data loginCredentialResponse
	if err = c.requestJSON(ctx, http.MethodPost, loginBufferURL, body, map[string]string{
		"Content-Type":          "application/json",
		"Ual-Access-Businessid": loginBusinessID,
		"Ual-Access-Timestamp":  ts,
		"Ual-Access-Nonce":      nonce,
		"Ual-Access-Signature":  sign(string(body), nonce, ts, loginAccessKey),
		"Cookie":                fmt.Sprintf("openid=%s; accesstoken=%s; refreshtoken=%s", creds.OpenID, creds.AccessToken, creds.RefreshToken),
	}, &data); err != nil {
		return "", err
	}
	code, err := credentialResponseCode(data.Code)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", &LoginBufferRejectedError{Code: code, Message: redactCredMessage(fmt.Sprint(data.Message), creds)}
	}
	values := stringSlicePath(data.ExtInfo, "list_s", "login_buffer", "value")
	if len(values) == 0 || values[0] == "" {
		return "", fmt.Errorf("login_buffer response is empty")
	}
	return values[0], nil
}

func (c *LoginBufferClient) RefreshCredentials(ctx context.Context, creds LoginBufferCredentials) (LoginBufferCredentials, error) {
	if creds.RefreshToken == "" {
		return LoginBufferCredentials{}, fmt.Errorf("missing refresh token")
	}
	// QR login originates from /pc_yyb/pcyyb_oauth (business "pc_yyb").
	// Set YYB_APPSTORE_REFRESH_MODE=legacy_auth to force the historical _auth route.
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("YYB_APPSTORE_REFRESH_MODE")))
	business, endpoint, key := mainBusinessID, mainRefreshURL, ""
	if mode == "legacy_auth" || creds.RefreshBusinessID == loginBusinessID {
		business, endpoint, key = loginBusinessID, refreshTokenURL, loginAccessKey
	}
	refreshed, err := c.requestCredentials(ctx, creds, endpoint, business, key)
	if err == nil {
		return refreshed, nil
	}
	var rejected *RefreshRejectedError
	if errors.As(err, &rejected) && rejected.Code == -109 && ctx.Err() == nil {
		// -109 is a gateway wrapper (RC_PARAMS_INVALID), not proof of revocation.
		// Query official /pc_yyb/pcyyb_check_login once to recover/rotate or reveal
		// the underlying WeChat error code (e.g. 42007 / 40030).
		checked, checkErr := c.CheckLogin(ctx, creds)
		if checkErr == nil {
			return checked, nil
		}
		return LoginBufferCredentials{}, fmt.Errorf("%w; %w", err, checkErr)
	}
	return LoginBufferCredentials{}, err
}

func (c *LoginBufferClient) CheckLogin(ctx context.Context, creds LoginBufferCredentials) (LoginBufferCredentials, error) {
	return c.requestCredentials(ctx, creds, checkLoginURL, mainBusinessID, "")
}

func (c *LoginBufferClient) requestCredentials(ctx context.Context, creds LoginBufferCredentials, endpoint, business, key string) (LoginBufferCredentials, error) {
	if creds.RefreshToken == "" {
		return LoginBufferCredentials{}, fmt.Errorf("missing refresh token")
	}
	body, err := json.Marshal(refreshTokenRequest{UserInfo: refreshTokenUserInfo{
		OpenID:       creds.OpenID,
		RefreshToken: creds.RefreshToken,
		AccessToken:  creds.AccessToken,
		LoginType:    defaultString(creds.LoginType, "WX"),
	}})
	if err != nil {
		return LoginBufferCredentials{}, err
	}
	ts, nonce := timestampMS(), nonce4()
	var data loginCredentialResponse
	if err = c.requestJSON(ctx, http.MethodPost, endpoint, body, map[string]string{
		"Content-Type":          "application/json",
		"Ual-Access-Businessid": business,
		"Ual-Access-Timestamp":  ts,
		"Ual-Access-Nonce":      nonce,
		"Ual-Access-Signature":  sign(string(body), nonce, ts, key),
	}, &data); err != nil {
		return LoginBufferCredentials{}, err
	}
	code, err := credentialResponseCode(data.Code)
	if err != nil {
		return LoginBufferCredentials{}, err
	}
	if code != 0 {
		op := "refresh_token"
		if endpoint == checkLoginURL {
			op = "check_login"
		}
		return LoginBufferCredentials{}, &RefreshRejectedError{
			Code:      code,
			Message:   redactCredMessage(fmt.Sprint(data.Message), creds),
			Operation: op,
		}
	}
	info := data.UserInfo
	if info == nil {
		info = data.UserInfoCamel
	}
	if openID := firstStringMap(info, "open_id", "openId"); openID != "" && openID != creds.OpenID {
		return LoginBufferCredentials{}, fmt.Errorf("credential response account mismatch")
	}
	expiresIn := defaultInt64(firstInt64Map(info, "expires_in", "expiresIn"), 7200)
	refreshed := creds
	refreshed.RefreshBusinessID = business
	refreshed.AccessToken = firstStringMap(info, "access_token", "accessToken")
	if rt := firstStringMap(info, "refresh_token", "refreshToken"); rt != "" {
		refreshed.RefreshToken = rt
	}
	refreshed.ExpiresIn = expiresIn
	refreshed.ExpiresAt = time.Now().Unix() + expiresIn
	if refreshed.AccessToken == "" {
		return LoginBufferCredentials{}, fmt.Errorf("refresh response missing access_token")
	}
	return refreshed, nil
}

func (c *LoginBufferClient) RefreshLoginBuffer(ctx context.Context, creds LoginBufferCredentials) (LoginBufferResult, error) {
	refreshed, err := c.RefreshCredentials(ctx, creds)
	if err != nil {
		return LoginBufferResult{}, err
	}
	lb, err := c.FetchLoginBuffer(ctx, refreshed)
	if err != nil {
		// Always return rotated credentials even if FetchLoginBuffer fails,
		// so callers persist the new access/refresh tokens instead of losing them.
		return LoginBufferResult{Credentials: refreshed, Refreshed: true}, err
	}
	return LoginBufferResult{LoginBuffer: lb, Credentials: refreshed, Refreshed: true}, nil
}

func (c *LoginBufferClient) FetchUserInfo(ctx context.Context, creds LoginBufferCredentials) (map[string]any, error) {
	ts, nonce := timestampMS(), nonce4()
	var data map[string]any
	err := c.requestJSON(ctx, http.MethodGet, userInfoURL, nil, map[string]string{
		"Ual-Access-Access-Token": creds.AccessToken,
		"Ual-Access-Login-Type":   "2",
		"Ual-Access-Openid":       creds.OpenID,
		"Ual-Access-Businessid":   "pc_yyb",
		"Ual-Access-Guid":         "web",
		"Ual-Access-Nonce":        nonce,
		"Ual-Access-Requestid":    fmt.Sprintf("%d", rand.Intn(9000)+1000),
		"Ual-Access-Signature":    sign("", nonce, ts, ""),
		"Ual-Access-Timestamp":    ts,
	}, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *LoginBufferClient) requestJSON(ctx context.Context, method, url string, body []byte, headers map[string]string, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data[:min(len(data), 200)]))
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode JSON: %w: %s", err, string(data[:min(len(data), 200)]))
	}
	return nil
}

type loginBufferRequest struct {
	ExtInfo loginExtInfo `json:"extInfo"`
}
type loginExtInfo struct {
	ListS loginListS `json:"listS"`
	ListI loginListI `json:"listI"`
}
type loginListS struct {
	UnionID     loginValueString `json:"unionid"`
	UserID      loginValueString `json:"user_id"`
	AccessToken loginValueString `json:"access_token"`
}
type loginListI struct {
	UserType loginValueInt `json:"user_type"`
}
type loginValueString struct {
	Value []string `json:"value"`
}
type loginValueInt struct {
	Value []int `json:"value"`
}
type refreshTokenRequest struct {
	UserInfo refreshTokenUserInfo `json:"userInfo"`
}
type refreshTokenUserInfo struct {
	OpenID       string `json:"openId"`
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
	LoginType    string `json:"loginType"`
}
type loginCredentialResponse struct {
	Code          json.RawMessage `json:"code"`
	Message       any             `json:"msg"`
	UserInfo      map[string]any  `json:"user_info"`
	ExtInfo       map[string]any  `json:"ext_info"`
	UserInfoCamel map[string]any  `json:"userInfo"`
}

func redactCredMessage(message string, creds LoginBufferCredentials) string {
	for _, secret := range []string{creds.AccessToken, creds.RefreshToken, creds.OpenID} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return message
}

func credentialResponseCode(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("credential response missing code")
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		var s string
		if sErr := json.Unmarshal(raw, &s); sErr == nil {
			n, pErr := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
			if pErr == nil {
				return int(n), nil
			}
		}
		return 0, fmt.Errorf("credential response code must be an integer")
	}
	n, err := strconv.ParseInt(number.String(), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("credential response code must be an integer")
	}
	return int(n), nil
}

func firstStringMap(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if s := stringFromMap(m, key); s != "" {
			return s
		}
	}
	return ""
}

func firstInt64Map(m map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if n := int64FromMap(m, key); n != 0 {
			return n
		}
		if s, ok := m[key].(string); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && n != 0 {
				return n
			}
		}
	}
	return 0
}

func timestampMS() string {
	return fmt.Sprintf("%d", time.Now().UnixMilli())
}

func nonce4() string {
	return fmt.Sprintf("%d", rand.Intn(10000))
}

func sign(body, nonce, ts, key string) string {
	sum := md5.Sum([]byte(body + ts + key + nonce))
	return hex.EncodeToString(sum[:])
}

func stringSlicePath(m map[string]any, path ...string) []string {
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[p]
	}
	arr, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func int64FromMap(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	default:
		return 0
	}
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func defaultInt64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}
