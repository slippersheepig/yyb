package protocol

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"yyb_go/internal/store"
)

const pskRenewMarginSeconds int64 = 60

type Config struct {
	ShortlinkTimeout        time.Duration
	LoginTimeout            time.Duration
	SessionTTL              time.Duration
	DNSCacheTTL             time.Duration
	MaxShortlinkConcurrency int
	MaxLoginConcurrency     int
	TCPProxy                string
	TCPProxyFallbackDirect  bool
}

func DefaultConfig() Config {
	return Config{
		ShortlinkTimeout:        8 * time.Second,
		LoginTimeout:            30 * time.Second,
		SessionTTL:              7 * 24 * time.Hour,
		DNSCacheTTL:             30 * time.Minute,
		MaxShortlinkConcurrency: 1000,
		MaxLoginConcurrency:     32,
		TCPProxyFallbackDirect:  true,
	}
}

type WmpfSession struct {
	Session          AppSession
	AutoAuth         AutoAuthState
	PSK              pskEntry
	ShortlinkTargets []Target
	CreatedAt        time.Time
	TCPProxy         string
}

type Pool struct {
	cfg Config
	db  *store.DB

	mu    sync.Mutex
	locks map[string]*sync.Mutex

	loginSem     chan struct{}
	shortlinkSem chan struct{}
}

func NewPool(cfg Config, db *store.DB) *Pool {
	def := DefaultConfig()
	if cfg.ShortlinkTimeout == 0 {
		cfg.ShortlinkTimeout = def.ShortlinkTimeout
	}
	if cfg.LoginTimeout == 0 {
		cfg.LoginTimeout = def.LoginTimeout
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = def.SessionTTL
	}
	if cfg.DNSCacheTTL == 0 {
		cfg.DNSCacheTTL = def.DNSCacheTTL
	}
	if cfg.MaxShortlinkConcurrency == 0 {
		cfg.MaxShortlinkConcurrency = def.MaxShortlinkConcurrency
	}
	if cfg.MaxLoginConcurrency == 0 {
		cfg.MaxLoginConcurrency = def.MaxLoginConcurrency
	}
	return &Pool{
		cfg:          cfg,
		db:           db,
		locks:        map[string]*sync.Mutex{},
		loginSem:     make(chan struct{}, cfg.MaxLoginConcurrency),
		shortlinkSem: make(chan struct{}, cfg.MaxShortlinkConcurrency),
	}
}

func (p *Pool) GetCode(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		hostAppID := st.Session.HostAppID
		if len(hostAppID) == 0 {
			hostAppID = hostAppIDDefault
		}
		plain := buildJSAPIPlaintext(st.Session.UIN, appID, jsLoginURL, jsLoginCmdID, nil, hostAppID, nil)
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, _, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		if len(code) == 0 {
			return nil, fmt.Errorf("wx.login returned empty code")
		}
		return map[string]any{"code": string(code), "errMsg": "login:ok"}, nil
	})
}

func (p *Pool) GetH5Code(ctx context.Context, loginBuffer, appID, redirectURI, scope, state string, accountID int64, tcpProxy string) (map[string]any, error) {
	callback, fullURL, resolvedScope, resolvedState, err := buildH5OAuthAuthorizeURL(appID, redirectURI, scope, state)
	if err != nil {
		return nil, err
	}
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		hostAppID := st.Session.HostAppID
		if len(hostAppID) == 0 {
			hostAppID = hostAppIDDefault
		}
		reqBytes := buildH5OAuthRequest(fullURL)
		plain := buildJSAPIPlaintext(st.Session.UIN, appID, h5OAuthURL, h5OAuthCmdID, reqBytes, hostAppID, nil)
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		_, reply, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		code, err := parseH5OAuthResult(reply, callback, resolvedState, 0)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"code":         code,
			"appid":        appID,
			"scope":        resolvedScope,
			"state":        resolvedState,
			"redirect_uri": callback,
			"mode":         "h5_oauth_auto",
		}, nil
	})
}

func (p *Pool) GetPhoneNumber(ctx context.Context, loginBuffer, appID string, accountID int64, tcpProxy string) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain := buildPhoneRequest(st.Session.UIN, appID)
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, resp, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return parseRawResponse(code, resp), nil
	})
}

func (p *Pool) OperateWXData(ctx context.Context, loginBuffer, appID string, payload map[string]any, accountID int64, tcpProxy string) (map[string]any, error) {
	return p.run(ctx, loginBuffer, accountID, tcpProxy, func(ctx context.Context, st WmpfSession) (map[string]any, error) {
		plain, err := buildOperateRequest(st.Session.UIN, appID, payload)
		if err != nil {
			return nil, err
		}
		envelope, err := buildTransferPacket(st.Session, plain)
		if err != nil {
			return nil, err
		}
		code, resp, err := p.sendEnvelope(ctx, st, envelope)
		if err != nil {
			return nil, err
		}
		return parseRawResponse(code, resp), nil
	})
}

func (p *Pool) Invalidate(ctx context.Context, accountID int64, tcpProxy string) error {
	return p.db.InvalidateSession(ctx, accountID, effectiveProxy(tcpProxy, p.cfg.TCPProxy))
}

func (p *Pool) CheckLiveness(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string) error {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	_, err := p.state(ctx, loginBuffer, accountID, effective)
	return err
}

// RefreshSessionPSK renews only the outer MMTLS 0-RTT PSK ticket via an anonymous
// handshake while preserving the existing WeChat AppSession (SendKey/RecvKey/F9/UIN).
func (p *Pool) RefreshSessionPSK(ctx context.Context, accountID int64, tcpProxy string) error {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	lock := p.lockFor(fmt.Sprintf("%d\x00%s", accountID, effective))
	lock.Lock()
	defer lock.Unlock()
	row, err := p.db.GetSessionAny(ctx, accountID, effective)
	if err != nil {
		return err
	}
	st, err := sessionFromBlob(row.SessionBlob)
	if err != nil {
		return err
	}
	_, err = p.refreshPSKLocked(ctx, st, accountID, effective)
	return err
}

// KeepSessionFresh ensures an active account has a cached WmpfSession and proactively
// renews the outer MMTLS PSK when it is within renewBefore of expiring, without
// touching WeChat when the existing PSK still has plenty of lifetime left.
func (p *Pool) KeepSessionFresh(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string, renewBefore time.Duration) error {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	row, err := p.db.GetSessionAny(ctx, accountID, effective)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if loginBuffer == "" {
				return nil
			}
			_, stateErr := p.state(ctx, loginBuffer, accountID, effective)
			return stateErr
		}
		return err
	}
	st, err := sessionFromBlob(row.SessionBlob)
	if err != nil {
		if loginBuffer == "" {
			return err
		}
		_, stateErr := p.state(ctx, loginBuffer, accountID, effective)
		return stateErr
	}
	now := time.Now().Unix()
	margin := int64(renewBefore.Seconds())
	if margin < pskRenewMarginSeconds {
		margin = pskRenewMarginSeconds
	}
	if st.PSK.PreSharedKey != "" && st.PSK.TicketEntry != "" && st.PSK.ExpiredAt > now+margin && row.ExpiresAt > now+margin {
		return nil
	}
	lock := p.lockFor(fmt.Sprintf("%d\x00%s", accountID, effective))
	lock.Lock()
	defer lock.Unlock()
	row, err = p.db.GetSessionAny(ctx, accountID, effective)
	if err != nil {
		return err
	}
	st, err = sessionFromBlob(row.SessionBlob)
	if err != nil {
		return err
	}
	now = time.Now().Unix()
	if st.PSK.PreSharedKey != "" && st.PSK.TicketEntry != "" && st.PSK.ExpiredAt > now+margin {
		// PSK itself is still fresh; just extend the local DB expires_at if it was capped earlier.
		uin := st.Session.UIN
		return p.db.PutSession(ctx, accountID, &uin, st.toBlob(), sessionExpiresAt(st, p.cfg.SessionTTL), effective)
	}
	_, err = p.refreshPSKLocked(ctx, st, accountID, effective)
	return err
}

func (p *Pool) run(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string, op func(context.Context, WmpfSession) (map[string]any, error)) (map[string]any, error) {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	st, err := p.state(ctx, loginBuffer, accountID, effective)
	if err == nil {
		res, opErr := op(ctx, st)
		var h5Rej *ErrH5OAuthBusinessRejected
		var slRej *ShortlinkRejectedError
		if opErr == nil || effective == "" || !p.cfg.TCPProxyFallbackDirect || opErr.Error() == "wx.login returned empty code" || errors.As(opErr, &h5Rej) || errors.As(opErr, &slRej) {
			return res, opErr
		}
		_ = p.Invalidate(ctx, accountID, effective)
		err = opErr
	}
	if effective != "" && p.cfg.TCPProxyFallbackDirect && (err == nil || !strings.Contains(err.Error(), "ManualAuthResponse")) {
		st, err = p.state(ctx, loginBuffer, accountID, "")
		if err != nil {
			return nil, err
		}
		return op(ctx, st)
	}
	return nil, err
}

func isPSKUsable(psk pskEntry, now int64) bool {
	return psk.PreSharedKey != "" && psk.TicketEntry != "" && psk.ExpiredAt > now+pskRenewMarginSeconds
}

func (p *Pool) state(ctx context.Context, loginBuffer string, accountID int64, tcpProxy string) (WmpfSession, error) {
	if row, err := p.db.GetSessionAny(ctx, accountID, tcpProxy); err == nil {
		if st, parseErr := sessionFromBlob(row.SessionBlob); parseErr == nil {
			now := time.Now().Unix()
			if isPSKUsable(st.PSK, now) && row.ExpiresAt > now {
				return st, nil
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return WmpfSession{}, err
	}
	lock := p.lockFor(fmt.Sprintf("%d\x00%s", accountID, tcpProxy))
	lock.Lock()
	defer lock.Unlock()
	if row, err := p.db.GetSessionAny(ctx, accountID, tcpProxy); err == nil {
		if st, parseErr := sessionFromBlob(row.SessionBlob); parseErr == nil {
			now := time.Now().Unix()
			if isPSKUsable(st.PSK, now) {
				// Preserve existing AppSession & PSK and heal any old short expires_at cap.
				uin := st.Session.UIN
				_ = p.db.PutSession(ctx, accountID, &uin, st.toBlob(), sessionExpiresAt(st, p.cfg.SessionTTL), tcpProxy)
				return st, nil
			}
			// AppSession is still intact; refresh only the outer anonymous MMTLS PSK
			// so we do not discard a live WeChat session or replay an old login_buffer.
			return p.refreshPSKLocked(ctx, st, accountID, tcpProxy)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return WmpfSession{}, err
	}
	acc, err := p.db.GetAccount(ctx, accountID)
	if err != nil {
		return WmpfSession{}, err
	}
	if err = acquire(ctx, p.loginSem); err != nil {
		return WmpfSession{}, err
	}
	defer release(p.loginSem)
	loginCtx, cancel := context.WithTimeout(ctx, p.cfg.LoginTimeout)
	defer cancel()
	st, err := p.loginAndSession(loginCtx, loginBuffer, tcpProxy)
	if err != nil {
		return WmpfSession{}, err
	}
	uin := st.Session.UIN
	_ = p.db.SetAccountUIN(ctx, acc.ID, uin)
	expiresAt := sessionExpiresAt(st, p.cfg.SessionTTL)
	blob := st.toBlob()
	if err = p.db.PutSession(ctx, accountID, &uin, blob, expiresAt, tcpProxy); err != nil {
		return WmpfSession{}, err
	}
	log.Printf("[pool] account %d ManualAuth succeeded (uin=%d, psk_lifetime=%ds, session_expires_at=%d)", accountID, uin, st.PSK.Lifetime, expiresAt)
	return st, nil
}

func (p *Pool) refreshPSKLocked(ctx context.Context, st WmpfSession, accountID int64, tcpProxy string) (WmpfSession, error) {
	if err := acquire(ctx, p.loginSem); err != nil {
		return WmpfSession{}, err
	}
	defer release(p.loginSem)
	loginCtx, cancel := context.WithTimeout(ctx, p.cfg.LoginTimeout)
	defer cancel()
	psk, shortTargets, err := p.fetchFreshPSK(loginCtx, tcpProxy)
	if err != nil {
		return WmpfSession{}, err
	}
	st.PSK = psk
	st.ShortlinkTargets = shortTargets
	st.CreatedAt = time.Now()
	st.TCPProxy = tcpProxy
	uin := st.Session.UIN
	expiresAt := sessionExpiresAt(st, p.cfg.SessionTTL)
	if err = p.db.PutSession(ctx, accountID, &uin, st.toBlob(), expiresAt, tcpProxy); err != nil {
		return WmpfSession{}, err
	}
	log.Printf("[pool] account %d refreshed MMTLS PSK (preserving AppSession, lifetime=%ds)", accountID, psk.Lifetime)
	return st, nil
}

func (p *Pool) fetchFreshPSK(ctx context.Context, tcpProxy string) (pskEntry, []Target, error) {
	targets, err := getLonglinkTargets(ctx, p.cfg.LoginTimeout, p.cfg.DNSCacheTTL)
	if err != nil {
		return pskEntry{}, nil, fmt.Errorf("HTTPDNS LongLink failed: %w", err)
	}
	targets = orderLonglinkTargets(targets, 6)
	var last error
	for _, t := range targets {
		mc, err := connectMmtls(ctx, t, p.cfg.LoginTimeout, tcpProxy, p.cfg.TCPProxyFallbackDirect)
		if err != nil {
			last = err
			continue
		}
		psks, err := mc.extractPSKs()
		mc.close()
		if err != nil {
			last = err
			continue
		}
		psk, ok := pickAccessPSK(psks)
		if !ok {
			last = fmt.Errorf("MMTLS handshake finished but no access PSK was issued")
			continue
		}
		shortTargets := getShortlinkTargets(ctx, p.cfg.ShortlinkTimeout, p.cfg.DNSCacheTTL)
		return psk, shortTargets, nil
	}
	if last == nil {
		last = fmt.Errorf("no LongLink candidates")
	}
	return pskEntry{}, nil, fmt.Errorf("all LongLink candidates failed for PSK refresh: %w", last)
}

func (p *Pool) lockFor(key string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.locks[key]; l != nil {
		return l
	}
	l := &sync.Mutex{}
	p.locks[key] = l
	return l
}

func (p *Pool) loginAndSession(ctx context.Context, loginBuffer, tcpProxy string) (WmpfSession, error) {
	if loginBuffer == "" {
		return WmpfSession{}, fmt.Errorf("login_buffer is empty")
	}
	targets, err := getLonglinkTargets(ctx, p.cfg.LoginTimeout, p.cfg.DNSCacheTTL)
	if err != nil {
		return WmpfSession{}, fmt.Errorf("HTTPDNS LongLink failed: %w", err)
	}
	targets = orderLonglinkTargets(targets, 6)
	meta, err := parseLoginBuffer(loginBuffer)
	if err != nil {
		return WmpfSession{}, err
	}
	appDeviceID := stableAppDeviceID(meta.DeviceID)
	var last error
	for _, t := range targets {
		mc, err := connectMmtls(ctx, t, p.cfg.LoginTimeout, tcpProxy, p.cfg.TCPProxyFallbackDirect)
		if err != nil {
			last = err
			continue
		}
		temp := &manualAuthTemp{}
		body, err := buildLoginBody(loginBuffer, meta.DeviceID, appDeviceID, temp)
		if err != nil {
			mc.close()
			return WmpfSession{}, err
		}
		if err = mc.sendApp(cmdManualAuth, body); err != nil {
			mc.close()
			last = err
			continue
		}
		resp, err := mc.recvApp()
		if err != nil {
			mc.close()
			last = err
			continue
		}
		if resp.Cmd != cmdManualAuth {
			mc.close()
			last = fmt.Errorf("manualauth failed: cmd=%d", resp.Cmd)
			continue
		}
		mar, err := parseLoginResponse(resp.Body, temp)
		if err != nil {
			mc.close()
			last = err
			continue
		}
		appSess, err := extractSession(mar)
		if err != nil {
			mc.close()
			// 上游已明确返回 ManualAuthResponse 业务拒绝/无会话块，无需继续轮询全部 6 个 LongLink IP
			if strings.Contains(err.Error(), "ManualAuthResponse") {
				return WmpfSession{}, err
			}
			last = err
			continue
		}
		appSess.DeviceID = meta.DeviceID
		appSess.HostAppID = meta.HostAppID
		autoAuth := autoAuthFromManualAuth(mar, appDeviceID)
		psks, err := mc.extractPSKs()
		mc.close()
		if err != nil {
			last = err
			continue
		}
		psk, ok := pickAccessPSK(psks)
		if !ok {
			last = fmt.Errorf("login finished but no access PSK was issued")
			continue
		}
		shortTargets := getShortlinkTargets(ctx, p.cfg.ShortlinkTimeout, p.cfg.DNSCacheTTL)
		return WmpfSession{
			Session:          appSess,
			AutoAuth:         autoAuth,
			PSK:              psk,
			ShortlinkTargets: shortTargets,
			CreatedAt:        time.Now(),
			TCPProxy:         tcpProxy,
		}, nil
	}
	if last == nil {
		last = fmt.Errorf("no LongLink candidates")
	}
	return WmpfSession{}, fmt.Errorf("all LongLink candidates failed: %w", last)
}

func (p *Pool) sendEnvelope(ctx context.Context, st WmpfSession, envelope []byte) ([]byte, []byte, error) {
	if err := acquire(ctx, p.shortlinkSem); err != nil {
		return nil, nil, err
	}
	defer release(p.shortlinkSem)
	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.ShortlinkTimeout)
	defer cancel()
	fallback := p.cfg.TCPProxyFallbackDirect
	if st.TCPProxy != "" {
		fallback = false
	}
	return send0RTT(reqCtx, st.ShortlinkTargets, st.PSK, st.Session.RecvKey, envelope, p.cfg.ShortlinkTimeout, st.TCPProxy, fallback)
}

func acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release(sem chan struct{}) {
	select {
	case <-sem:
	default:
	}
}

func effectiveProxy(req, def string) string {
	if req != "" {
		return req
	}
	return def
}

func sessionExpiresAt(st WmpfSession, ttl time.Duration) int64 {
	now := time.Now().Unix()
	exp := st.PSK.ExpiredAt
	ttlExp := now + int64(ttl.Seconds())
	if exp == 0 || exp > ttlExp {
		exp = ttlExp
	}
	return exp
}

func (st WmpfSession) toBlob() map[string]any {
	out := map[string]any{
		"session": map[string]any{
			"send_key":   encBytes(st.Session.SendKey),
			"recv_key":   encBytes(st.Session.RecvKey),
			"f9":         encBytes(st.Session.F9),
			"uin":        st.Session.UIN,
			"ticket":     encBytes(st.Session.Ticket),
			"device_id":  encBytes(st.Session.DeviceID),
			"host_appid": encBytes(st.Session.HostAppID),
		},
		"psk_entry":         st.PSK,
		"shortlink_targets": targetsToAny(st.ShortlinkTargets),
		"tcp_proxy":         st.TCPProxy,
	}
	if len(st.AutoAuth.Key) > 0 || len(st.AutoAuth.EncKey) > 0 || st.AutoAuth.AttemptedAt > 0 {
		out["auto_auth"] = map[string]any{
			"device":       encBytes(st.AutoAuth.Device),
			"key":          encBytes(st.AutoAuth.Key),
			"enc_key":      encBytes(st.AutoAuth.EncKey),
			"attempted_at": st.AutoAuth.AttemptedAt,
		}
	}
	return out
}

func sessionFromBlob(blob map[string]any) (WmpfSession, error) {
	sm, ok := blob["session"].(map[string]any)
	if !ok {
		return WmpfSession{}, fmt.Errorf("session_blob missing session")
	}
	pm, ok := blob["psk_entry"].(map[string]any)
	if !ok {
		return WmpfSession{}, fmt.Errorf("session_blob missing psk_entry")
	}
	st := WmpfSession{
		Session: AppSession{
			SendKey:   decBytes(sm["send_key"]),
			RecvKey:   decBytes(sm["recv_key"]),
			F9:        decBytes(sm["f9"]),
			UIN:       int64FromAny(sm["uin"]),
			Ticket:    decBytes(sm["ticket"]),
			DeviceID:  decBytes(sm["device_id"]),
			HostAppID: decBytes(sm["host_appid"]),
		},
		PSK: pskEntry{
			PSKType:      int(int64FromAny(pm["psk_type"])),
			PreSharedKey: stringAny(pm["pre_shared_key"]),
			TicketEntry:  stringAny(pm["ticket_entry"]),
			Lifetime:     int64FromAny(pm["lifetime"]),
			ExpiredAt:    int64FromAny(pm["expired_at"]),
		},
		ShortlinkTargets: targetsFromAny(blob["shortlink_targets"]),
		TCPProxy:         stringAny(blob["tcp_proxy"]),
		CreatedAt:        time.Now(),
	}
	if am, ok := blob["auto_auth"].(map[string]any); ok {
		st.AutoAuth = AutoAuthState{
			Device:      decBytes(am["device"]),
			Key:         decBytes(am["key"]),
			EncKey:      decBytes(am["enc_key"]),
			AttemptedAt: int64FromAny(am["attempted_at"]),
		}
	}
	if len(st.ShortlinkTargets) == 0 {
		st.ShortlinkTargets = []Target{{IP: "120.241.131.173", Port: 80}}
	}
	if len(st.Session.SendKey) == 0 || len(st.Session.RecvKey) == 0 || st.Session.UIN == 0 {
		return WmpfSession{}, fmt.Errorf("session_blob incomplete")
	}
	return st, nil
}

func encBytes(b []byte) map[string]any {
	if b == nil {
		b = []byte{}
	}
	return map[string]any{"__bytes__": hex.EncodeToString(b)}
}

func decBytes(v any) []byte {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["__bytes__"].(string); ok {
			b, _ := hex.DecodeString(s)
			return b
		}
	}
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	return nil
}

func targetsToAny(ts []Target) [][]any {
	out := make([][]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, []any{t.IP, t.Port})
	}
	return out
}

func targetsFromAny(v any) []Target {
	var out []Target
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	for _, it := range arr {
		pair, ok := it.([]any)
		if !ok || len(pair) < 2 {
			continue
		}
		out = append(out, Target{IP: stringAny(pair[0]), Port: int(int64FromAny(pair[1]))})
	}
	return out
}

func stringAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func int64FromAny(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	default:
		return 0
	}
}
