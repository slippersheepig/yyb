package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"yyb_go/internal/protocol"
	"yyb_go/internal/qr"
	"yyb_go/internal/store"
	"yyb_go/internal/tgbot"
)

type Config struct {
	ResourceRoot      string
	DBFilename        string
	TCPProxy          string
	SessionTTL        time.Duration
	KeepAliveInterval time.Duration
	KeepAliveAhead    time.Duration
	RequestTimeout    time.Duration
	AvatarTimeout     time.Duration
	ScanTimeout       time.Duration
	QRSessionTTL      time.Duration
	APIToken          string
	AllowedIPs        []string
	TGBotToken        string
	TGAdminIDs        []int64
	WebUser           string
	WebPass           string
	WxGzhLink         string
	WxGzhName         string
	AutopostURL       string // autopost service URL for JD verification
	AutopostToken     string // Bearer token for autopost service auth
	WebDomain         string // this server's external URL (e.g. https://yyb.example.com)
	ListenPort        int    // this server's listen port (for fallback WebDomain)
}

type App struct {
	cfg       Config
	resources resources
	db        *store.DB
	pool      *protocol.Pool
	qr        *qr.Client
	tgBot     *tgbot.Bot
	webAuth   *WebSessionManager

	mu           sync.Mutex
	qrSessions   map[string]*qr.Session
	ualFailUntil map[int64]time.Time
}

var swaggerDocsHandler = httpSwagger.Handler(
	httpSwagger.URL("/openapi.json"),
	httpSwagger.DocExpansion("list"),
	httpSwagger.DeepLinking(true),
	httpSwagger.DefaultModelsExpandDepth(httpSwagger.ShowModel),
)

func NewApp(cfg Config) (*App, error) {
	if cfg.ResourceRoot == "" {
		cfg.ResourceRoot = filepath.Join(".", "resource")
	}
	if cfg.DBFilename == "" {
		cfg.DBFilename = DefaultDBFilename
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 8 * time.Second
	}
	if cfg.AvatarTimeout == 0 {
		cfg.AvatarTimeout = 10 * time.Second
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 7 * 24 * time.Hour
	}
	if cfg.KeepAliveInterval == 0 {
		cfg.KeepAliveInterval = 2 * time.Minute
	}
	if cfg.KeepAliveAhead == 0 {
		cfg.KeepAliveAhead = 5 * time.Minute
	}
	if cfg.QRSessionTTL == 0 {
		cfg.QRSessionTTL = 5 * time.Minute
	}
	res, err := ensureResources(cfg.ResourceRoot)
	if err != nil {
		return nil, err
	}
	dbPath, err := prepareDBPath(res.DB, cfg.DBFilename)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	poolCfg := protocol.DefaultConfig()
	poolCfg.SessionTTL = cfg.SessionTTL
	poolCfg.ShortlinkTimeout = cfg.RequestTimeout
	poolCfg.TCPProxy = cfg.TCPProxy
	pool := protocol.NewPool(poolCfg, db)
	webAuth := NewWebSessionManager(cfg.WebUser, cfg.WebPass)
	return &App{
		cfg:          cfg,
		resources:    res,
		db:           db,
		pool:         pool,
		qr:           qr.NewClient(cfg.RequestTimeout),
		qrSessions:   map[string]*qr.Session{},
		ualFailUntil: map[int64]time.Time{},
		webAuth:      webAuth,
	}, nil
}

// StartAutoRefresh launches a background goroutine aligned with official PC YYB
// (AndrowsSvr.exe):
//   - Lightweight DB scan every KeepAliveInterval (default 2m; no network traffic
//     unless an account is actually within its renewal window).
//   - Token-only refresh via /pc_yyb/pcyyb_refresh_token (and /pc_yyb/pcyyb_check_login
//     on -109) when access_token expires within KeepAliveAhead (default 5m), persisting
//     rotated tokens immediately without prematurely minting login_buffer.
//   - Proactive anonymous MMTLS PSK renewal for active WMPF sessions.
func (a *App) StartAutoRefresh(ctx context.Context) {
	if a.cfg.KeepAliveInterval < 0 {
		log.Printf("[autoRefresh] disabled by configuration")
		return
	}
	interval := a.cfg.KeepAliveInterval
	if interval == 0 {
		interval = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Run once on startup after a short delay to let the server bind first.
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	a.runAutoRefreshSafe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runAutoRefreshSafe(ctx)
		}
	}
}

func (a *App) runAutoRefreshSafe(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[autoRefresh] recovered panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	a.autoRefreshAll(ctx)
}

func (a *App) isUALBackedOff(accountID int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.ualFailUntil[accountID]
	return ok && time.Now().Before(until)
}

func (a *App) setUALBackoff(accountID int64, d time.Duration) {
	a.mu.Lock()
	a.ualFailUntil[accountID] = time.Now().Add(d)
	a.mu.Unlock()
}

func (a *App) clearUALBackoff(accountID int64) {
	a.mu.Lock()
	delete(a.ualFailUntil, accountID)
	a.mu.Unlock()
}

func (a *App) autoRefreshAll(ctx context.Context) {
	accounts, err := a.db.ListAccounts(ctx)
	if err != nil {
		log.Printf("[autoRefresh] ListAccounts error: %v", err)
		return
	}
	now := time.Now().Unix()
	aheadSec := int64(a.cfg.KeepAliveAhead.Seconds())
	if aheadSec <= 0 {
		aheadSec = 5 * 60
	}
	for _, acc := range accounts {
		if acc.Status != nil && *acc.Status == "expired" {
			continue
		}
		// 1. 仅在 access_token 进入提前刷新窗口时执行纯 Token 续期并立即落库（不提前拉取 login_buffer）
		if acc.Credentials != nil && !a.isUALBackedOff(acc.ID) {
			creds := protocol.CredentialsFromMap(acc.Credentials)
			if creds.RefreshToken != "" && creds.ExpiresAt <= now+aheadSec {
				a.refreshOneAccount(ctx, acc)
			}
		}
		// 2. 维护底层 WMPF 会话：确保会话已预热落库，并在外层 MMTLS PSK 临近过期时匿名续期 PSK（保留 AppSession）
		keepCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := a.pool.KeepSessionFresh(keepCtx, acc.LoginBuffer, acc.ID, a.cfg.TCPProxy, 30*time.Minute); err != nil {
			log.Printf("[autoRefresh] account %d (%s) WMPF session keep-fresh skipped: %v", acc.ID, acc.OpenID, err)
		}
		cancel()
	}
}

func (a *App) refreshOneAccount(ctx context.Context, acc *store.WechatAccount) {
	if acc.Credentials == nil {
		return
	}
	creds := protocol.CredentialsFromMap(acc.Credentials)
	if creds.RefreshToken == "" {
		return
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	refreshed, err := a.qr.LoginBuffers().RefreshCredentials(refreshCtx, creds)
	if err == nil {
		acc.Credentials = refreshed.ToMap()
		_ = a.db.SetAccountCredential(context.WithoutCancel(ctx), acc.ID, acc.LoginBuffer, acc.Credentials)
		_ = a.db.SetAccountStatus(context.WithoutCancel(ctx), acc.ID, "alive")
		a.clearUALBackoff(acc.ID)
		log.Printf("[autoRefresh] account %d (%s) OAuth token refreshed OK (expires_in=%ds, business=%s)", acc.ID, acc.OpenID, refreshed.ExpiresIn, refreshed.RefreshBusinessID)
		return
	}
	// 退避冷却避免每 2 分钟重复冲击腾讯 UAL；同时绝不清空可能仍可用的底层 WMPF AppSession/AutoAuth
	if protocol.IsHardCredentialRevoked(err) {
		a.setUALBackoff(acc.ID, 6*time.Hour)
		log.Printf("[autoRefresh] account %d (%s) OAuth revoked upstream (preserving WMPF session): %v", acc.ID, acc.OpenID, err)
		return
	}
	a.setUALBackoff(acc.ID, 30*time.Minute)
	log.Printf("[autoRefresh] account %d (%s) UAL refresh failed (backoff 30m): %v", acc.ID, acc.OpenID, err)
}

func (a *App) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// DB returns the underlying store.DB (used by the Telegram bot).
func (a *App) DB() *store.DB { return a.db }

// SetTelegramBot wires the bot so the App can push login notifications.
func (a *App) SetTelegramBot(bot *tgbot.Bot) { a.tgBot = bot }

func (a *App) Handler() http.Handler {
	if os.Getenv(gin.EnvGinMode) == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// ── 公开路由（无需鉴权）──
	router.Any("/", gin.WrapF(a.handleIndex))
	router.Any("/scan", gin.WrapF(a.handleScan))
	router.Any("/login", gin.WrapF(a.handleLogin))
	router.Any("/logout", gin.WrapF(a.handleLogout))
	router.Any("/health", func(c *gin.Context) {
		writeJSON(c.Writer, http.StatusOK, gin.H{"ok": true})
	})
	router.StaticFS("/static", http.Dir(a.resources.Static))
	router.Any("/qr", gin.WrapF(a.handleQRRoot))
	router.Any("/qr/*path", gin.WrapF(a.handleQR))

	// ── Web 管理路由（需 admin session）──
	adminGroup := router.Group("", a.RequireAdminAuth())
	adminGroup.Any("/admin", gin.WrapF(a.handleAdmin))
	adminGroup.Any("/api/admin/accounts", gin.WrapF(a.handleAdminAccounts))
	adminGroup.Any("/api/admin/accounts/refresh", gin.WrapF(a.handleAdminRefresh))
	adminGroup.Any("/api/admin/accounts/delete", gin.WrapF(a.handleAdminDelete))

	// ── 用户路由（需 user session 或 admin session）──
	userGroup := router.Group("", a.RequireUserAuth())
	userGroup.Any("/my", gin.WrapF(a.handleMy))
	userGroup.Any("/api/my/status", gin.WrapF(a.handleMyStatus))
	userGroup.Any("/api/my/avatar", gin.WrapF(a.handleMyAvatar))
	userGroup.Any("/api/my/jd-check", gin.WrapF(a.handleMyJdCheck))
	userGroup.Any("/api/my/jd-cookie", gin.WrapF(a.handleMyJdCookie))
	userGroup.Any("/api/wx/bind-code", gin.WrapF(a.handleWxBindCode))
	userGroup.Any("/api/wx/bind-status", gin.WrapF(a.handleWxBindStatus))

	// ── 公开的微信绑定/取件路由──
	router.Any("/api/wx/bind", gin.WrapF(a.handleWxBind))
	router.Any("/api/wx/pending", gin.WrapF(a.handleWxPending))

	// ── 受保护路由（需要鉴权）──
	protected := router.Group("", a.authMiddleware())
	protected.Any("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})
	protected.Any("/docs/*path", gin.WrapF(a.handleDocs))
	protected.Any("/openapi.json", gin.WrapF(a.handleOpenAPI))
	protected.Any("/accounts", gin.WrapF(a.handleAccountsRoot))
	protected.Any("/accounts/avatar", gin.WrapF(a.handleAccountAvatar))
	protected.Any("/accounts/refresh", gin.WrapF(a.handleAccountRefresh))
	protected.Any("/accounts/resync", gin.WrapF(a.handleAccountResync))
	protected.Any("/wxapp/getCode", gin.WrapF(a.handleGetCode))
	protected.Any("/wxapp/getH5Code", gin.WrapF(a.handleGetH5Code))
	protected.Any("/wx/h5code", gin.WrapF(a.handleGetH5Code))
	protected.Any("/wxapp/getPhoneNumber", gin.WrapF(a.handleGetPhoneNumber))
	protected.Any("/wxapp/operateWxData", gin.WrapF(a.handleOperateWXData))
	protected.Any("/api/wx/push", gin.WrapF(a.handleWxPush))

	router.NoRoute(func(c *gin.Context) {
		writeError(c.Writer, http.StatusNotFound, "not found")
	})

	return router
}

func (a *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		adminCookie, err := c.Cookie("yyb_admin")
		if err == nil && a.webAuth.IsValidAdmin(adminCookie) {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		for _, allowed := range a.cfg.AllowedIPs {
			if clientIP == allowed {
				c.Next()
				return
			}
		}

		if a.cfg.APIToken != "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(a.cfg.APIToken)) == 1 {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthorized", "data": nil})
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Check admin session; redirect to login if not authenticated
	cookie, err := r.Cookie("yyb_admin")
	if err != nil || !a.webAuth.IsValidAdmin(cookie.Value) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "index.html"), fallbackIndexHTML)
}

func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "scan.html"), fallbackScanHTML)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		serveFileOrText(w, r, filepath.Join(a.resources.Templates, "login.html"), fallbackLoginHTML)
	case http.MethodPost:
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")
		// 也支持 JSON body: {"username":"...","password":"..."}
		if user == "" || pass == "" {
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				user = body.Username
				pass = body.Password
			}
		}
		if a.webAuth.CheckAdminLogin(user, pass) {
			token, expiry := a.webAuth.CreateAdminSession(24 * time.Hour)
			http.SetCookie(w, sessionCookie(r, "yyb_admin", token, expiry))
			writeJSON(w, http.StatusOK, gin.H{"ok": true, "redirect": "/admin"})
		} else {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		}
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cookie, err := r.Cookie("yyb_admin")
	if err == nil {
		a.webAuth.DestroyAdminSession(cookie.Value)
	}
	clearCookie := sessionCookie(r, "yyb_admin", "", time.Now())
	clearCookie.MaxAge = -1
	http.SetCookie(w, clearCookie)
	writeJSON(w, http.StatusOK, gin.H{"ok": true, "redirect": "/login"})
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serveFileOrText(w, r, filepath.Join(a.resources.Templates, "index.html"), fallbackIndexHTML)
}

func (a *App) handleMy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	src := filepath.Join(a.resources.Templates, "user.html")
	if _, err := os.Stat(src); err != nil {
		serveFileOrText(w, r, src, fallbackMyHTML)
		return
	}
	http.ServeFile(w, r, src)
}

func (a *App) handleDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.Path == "/docs/" {
		http.Redirect(w, r, "/docs/index.html", http.StatusMovedPermanently)
		return
	}
	swaggerDocsHandler.ServeHTTP(w, r)
}

func (a *App) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeRawJSON(w, http.StatusOK, openAPISpec)
}

func (a *App) handleQRRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/qr" {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.pruneQR()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout+35*time.Second)
	defer cancel()
	img, err := a.qr.GetQRCodeImage(ctx)
	if err != nil {
		log.Printf("[qr] GetQRCodeImage failed: %v", err)
		writeError(w, http.StatusFailedDependency, err.Error())
		return
	}
	a.mu.Lock()
	a.qrSessions[img.Session.ID] = img.Session
	keep := make(map[string]bool, len(a.qrSessions))
	for sid := range a.qrSessions {
		keep[sid] = true
	}
	a.mu.Unlock()
	path := a.resources.qrPath(img.Session.ID)
	_ = os.WriteFile(path, img.ImageBytes, 0o644)
	a.cleanupQR(keep)
	out := map[string]any{
		"session_id": img.Session.ID,
		"status":     img.Session.Status,
		"image_url":  "/qr/" + img.Session.ID + "/image",
	}
	if r.URL.Query().Get("as_base64") == "true" {
		out["image_base64"] = qr.DataURIJPEG(img.ImageBytes)
	} else {
		out["image_base64"] = nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/qr/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "qr session not found")
		return
	}
	sessionID, action := parts[0], parts[1]
	switch action {
	case "image":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		path := a.resources.qrPath(sessionID)
		if _, err := os.Stat(path); err != nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		http.ServeFile(w, r, path)
	case "poll":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.PollQRCode(r.Context(), sess)
		if err != nil {
			log.Printf("[qr] PollQRCode failed: %v", err)
			writeError(w, http.StatusFailedDependency, err.Error())
			return
		}
		if terminalQR(result.Status) {
			a.dropQRSession(sessionID)
		}
		writeJSON(w, http.StatusOK, result)
	case "confirm":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		sess := a.getQRSession(sessionID)
		if sess == nil {
			writeError(w, http.StatusNotFound, "qr session not found")
			return
		}
		result, err := a.qr.GetLoginBuffer(r.Context(), sess)
		if err != nil {
			writeError(w, http.StatusConflict, "buffer not ready: "+err.Error())
			return
		}
		var userInfo map[string]any
		if ui, err := a.qr.LoginBuffers().FetchUserInfo(r.Context(), result.Credentials); err == nil {
			userInfo = ui
		}
		acc, err := a.storeFromScan(r.Context(), result.LoginBuffer, result.Credentials, userInfo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.dropQRSession(sessionID)
		// Create a user session and set cookie for the scanning user.
		userToken, err := a.db.CreateUserSession(r.Context(), acc.ID, 7*24*time.Hour)
		if err == nil && userToken != "" {
			http.SetCookie(w, sessionCookie(r, "yyb_user", userToken, time.Now().Add(7*24*time.Hour)))
		}
		resp := gin.H{"account": acc.Public(), "redirect": "/my"}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeError(w, http.StatusNotFound, "qr session not found")
	}
}

func (a *App) handleAccountsRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts, err := a.db.ListAccounts(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]store.AccountPublic, 0, len(accounts))
		for _, acc := range accounts {
			out = append(out, acc.Public())
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		acc, ok := a.resolveAccountFromQuery(w, r)
		if !ok {
			return
		}
		if err := a.db.DeleteAccount(r.Context(), acc.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": acc.ID, "openid": acc.OpenID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAccountAvatar(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/avatar" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	acc, ok := a.resolveAccountFromQuery(w, r)
	if !ok {
		return
	}
	a.serveAvatar(w, r, acc)
}

func (a *App) handleAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/refresh" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.refreshAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	status := a.refreshLiveness(r.Context(), acc)
	writeJSON(w, http.StatusOK, refreshOut(acc, status))
}

func (a *App) handleAccountResync(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/accounts/resync" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountRefIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		a.resyncAll(w, r)
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	updated, err := a.resyncProfile(r.Context(), acc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated.Public())
}

var builtinNonMiniProgramAppIDs = map[string]string{
	"wx2f5d8f9715c59d10": "京东网页登录护照公众号",
	"wx5cd60c5d4817a188": "腾讯电脑管家网站应用",
}

func (a *App) handleGetCode(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getCode") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetCode)
}

func (a *App) handleGetH5Code(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/wx/h5code" && r.URL.Path != "/wxapp/getH5Code" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Ref         string         `json:"ref"`
		AppID       string         `json:"app_id"`
		AppIDAlt    string         `json:"appid"`
		RedirectURI string         `json:"redirect_uri"`
		Scope       string         `json:"scope"`
		State       string         `json:"state"`
		Payload     map[string]any `json:"payload"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	appID := strings.TrimSpace(body.AppID)
	if appID == "" {
		appID = strings.TrimSpace(body.AppIDAlt)
	}
	redirectURI := strings.TrimSpace(body.RedirectURI)
	scope := strings.TrimSpace(body.Scope)
	state := strings.TrimSpace(body.State)
	if body.Payload != nil {
		if redirectURI == "" {
			redirectURI = strings.TrimSpace(stringFromAny(body.Payload["redirect_uri"]))
		}
		if scope == "" {
			scope = strings.TrimSpace(stringFromAny(body.Payload["scope"]))
		}
		if state == "" {
			state = strings.TrimSpace(stringFromAny(body.Payload["state"]))
		}
	}
	if strings.TrimSpace(body.Ref) == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}
	if appID == "" {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}
	if redirectURI == "" {
		writeError(w, http.StatusBadRequest, "redirect_uri is required")
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	result, err := a.invokeWXApp(r.Context(), acc, appID, nil, func(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
		return a.pool.GetH5Code(ctx, acc.LoginBuffer, appID, redirectURI, scope, state, acc.ID, a.cfg.TCPProxy)
	})
	if err != nil {
		log.Printf("[h5code] account %d (%s) app=%s scope=%s failed: %v", acc.ID, acc.OpenID, appID, scope, err)
		var expired accountExpiredError
		if errors.As(err, &expired) {
			writeError(w, http.StatusConflict, expired.clientMessage())
			return
		}
		// Return 424 Failed Dependency instead of 502 Bad Gateway so reverse proxies
		// like Cloudflare pass our structured JSON error body straight through instead
		// of replacing 502 responses with a generic edge gateway error page.
		writeError(w, http.StatusFailedDependency, "h5code call failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"openid": acc.OpenID, "result": result})
}

func (a *App) handleGetPhoneNumber(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/getPhoneNumber") {
		return
	}
	a.callWXApp(w, r, false, a.invokeGetPhoneNumber)
}

func (a *App) handleOperateWXData(w http.ResponseWriter, r *http.Request) {
	if !acceptWXAppRoute(w, r, "/wxapp/operateWxData") {
		return
	}
	a.callWXApp(w, r, true, a.invokeOperateWXData)
}

func acceptWXAppRoute(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.URL.Path != path {
		writeError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

type accountRefIn struct {
	Ref string `json:"ref"`
}

type wxappRequest struct {
	Ref     string         `json:"ref"`
	AppID   string         `json:"app_id"`
	Payload map[string]any `json:"payload"`
}

type wxappCall func(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error)

func (a *App) callWXApp(w http.ResponseWriter, r *http.Request, requirePayload bool, call wxappCall) {
	var body wxappRequest
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}
	if body.AppID == "" {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}
	if requirePayload && body.Payload == nil {
		writeError(w, http.StatusBadRequest, "payload is required")
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	result, err := a.invokeWXApp(r.Context(), acc, body.AppID, body.Payload, call)
	if err != nil {
		log.Printf("[wxapp] account %d (%s) app=%s failed: %v", acc.ID, acc.OpenID, body.AppID, err)
		var expired accountExpiredError
		switch {
		case errors.As(err, &expired):
			writeError(w, http.StatusConflict, expired.clientMessage())
		case strings.Contains(err.Error(), "non-miniprogram AppID"):
			writeError(w, http.StatusForbidden, err.Error())
		default:
			writeError(w, http.StatusFailedDependency, "call failed: "+err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"openid": acc.OpenID, "result": result})
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (a *App) resolveAccountFromQuery(w http.ResponseWriter, r *http.Request) (*store.WechatAccount, bool) {
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref query param is required")
		return nil, false
	}
	return a.resolveAccountRef(w, r, ref)
}

func (a *App) resolveAccountRef(w http.ResponseWriter, r *http.Request, ref string) (*store.WechatAccount, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}
	acc, err := a.db.ResolveAccount(r.Context(), ref)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "account not found: "+ref)
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}
	return acc, true
}

func (a *App) refreshAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, refreshOut(acc, a.refreshLiveness(r.Context(), acc)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) resyncAll(w http.ResponseWriter, r *http.Request) {
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]store.AccountPublic, 0, len(accounts))
	for _, acc := range accounts {
		updated, err := a.resyncProfile(r.Context(), acc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, updated.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) serveAvatar(w http.ResponseWriter, r *http.Request, acc *store.WechatAccount) {
	if acc.Avatar != nil && *acc.Avatar != "" {
		if _, err := os.Stat(*acc.Avatar); err == nil {
			w.Header().Set("Content-Type", "image/jpeg")
			http.ServeFile(w, r, *acc.Avatar)
			return
		}
		if strings.HasPrefix(*acc.Avatar, "http://") || strings.HasPrefix(*acc.Avatar, "https://") {
			http.Redirect(w, r, *acc.Avatar, http.StatusFound)
			return
		}
	}
	writeError(w, http.StatusNotFound, "no avatar")
}

func (a *App) storeFromScan(ctx context.Context, loginBuffer string, creds protocol.LoginBufferCredentials, userInfo map[string]any) (*store.WechatAccount, error) {
	openid := creds.OpenID
	nick := pickNickname(userInfo, creds.Nickname)
	avatar := a.resolveAvatar(ctx, openid, userInfo)
	status := "alive"
	acc, err := a.db.UpsertAccount(ctx, openid, loginBuffer, stringPtrMaybe(nick), stringPtrMaybe(nick), stringPtrMaybe(avatar), userInfo, creds.ToMap(), &status)
	if err != nil {
		return nil, err
	}
	// 重新扫码成功，清理旧会话缓存、退避状态与上一轮残留的京东二验风险链接
	a.clearUALBackoff(acc.ID)
	_ = a.db.InvalidateAllSessions(ctx, acc.ID)
	_ = a.db.SetJdRiskURL(ctx, acc.ID, "")
	// 趁刚拿到的 login_buffer 尚在有效期内，立即建立 WMPF 会话并落库，避免后续闲置导致 login_buffer 过期未消费
	warmupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	if warmErr := a.pool.CheckLiveness(warmupCtx, loginBuffer, acc.ID, a.cfg.TCPProxy); warmErr != nil {
		log.Printf("[storeFromScan] account %d (%s) session warmup failed (will retry on demand): %v", acc.ID, acc.OpenID, warmErr)
	} else if refreshedAcc, getErr := a.db.GetAccount(ctx, acc.ID); getErr == nil && refreshedAcc != nil {
		acc = refreshedAcc
	}
	cancel()
	// Notify Telegram admins about the new login.
	if a.tgBot != nil && acc != nil {
		ev := tgbot.NewLoginEvent{
			OpenID:   acc.OpenID,
			Nickname: nick,
			UIN:      acc.UIN,
			Avatar:   avatar,
		}
		a.tgBot.NotifyLogin(ev)
	}
	return acc, nil
}

func (a *App) refreshLiveness(ctx context.Context, acc *store.WechatAccount) string {
	if acc.LoginBuffer == "" {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
		return "expired"
	}
	// 尝试通过微信底层 WMPF MMTLS 会话校验账号存活
	proxy := a.cfg.TCPProxy
	err := a.pool.CheckLiveness(ctx, acc.LoginBuffer, acc.ID, proxy)
	if err == nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
		return "alive"
	}
	// 只有当明确是 manualauth 认证失败/凭据被微信拒绝时，先尝试按需刷新 login_buffer 再判定是否 expired
	if isLoginBufferExpiredErr(err) {
		if refreshed, reason := a.tryRefreshLoginBuffer(ctx, acc); refreshed {
			_ = a.db.InvalidateAllSessions(ctx, acc.ID)
			if retryErr := a.pool.CheckLiveness(ctx, acc.LoginBuffer, acc.ID, proxy); retryErr == nil {
				_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
				return "alive"
			} else if !isLoginBufferExpiredErr(retryErr) {
				log.Printf("[refreshLiveness] 账号 %d (%s) 刷新 login_buffer 后检测遇到临时错误: %v", acc.ID, acc.OpenID, retryErr)
			} else {
				log.Printf("[refreshLiveness] 账号 %d (%s) 刷新 login_buffer 后微信认证仍失效: %v", acc.ID, acc.OpenID, retryErr)
				_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
				return "expired"
			}
		} else {
			log.Printf("[refreshLiveness] 账号 %d (%s) 微信认证已失效: %v (%s)", acc.ID, acc.OpenID, err, reason)
			_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
			return "expired"
		}
	}
	// 网络超时等临时错误，保持原有状态（默认 alive）
	currentStatus := "alive"
	if acc.Status != nil && *acc.Status != "" {
		currentStatus = *acc.Status
	}
	return currentStatus
}

func (a *App) resyncProfile(ctx context.Context, acc *store.WechatAccount) (*store.WechatAccount, error) {
	nick := pickNickname(acc.UserInfo, deref(acc.Nickname))
	avatar := a.resolveAvatar(ctx, acc.OpenID, acc.UserInfo)
	if avatar == "" {
		avatar = deref(acc.Avatar)
	}
	if err := a.db.SetAccountProfile(ctx, acc.ID, stringPtrMaybe(nick), stringPtrMaybe(avatar), acc.UserInfo); err != nil {
		return nil, err
	}
	return a.db.GetAccount(ctx, acc.ID)
}

type accountExpiredError struct {
	openid string
	detail string
}

func (e accountExpiredError) Error() string {
	if e.detail != "" {
		return "account expired: " + e.openid + " (" + e.detail + ")"
	}
	return "account expired: " + e.openid
}

func (e accountExpiredError) clientMessage() string {
	if e.detail != "" {
		return "account login_buffer expired (" + e.detail + "); re-scan required"
	}
	return "account login_buffer expired (refresh failed); re-scan required"
}

func isLoginBufferExpiredErr(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "manualauth failed") ||
		strings.Contains(errStr, "manualauthresponse missing") ||
		strings.Contains(errStr, "manualauthresponse rejected") ||
		strings.Contains(errStr, "manualauthresponse session fields incomplete") ||
		strings.Contains(errStr, "login_buffer is empty") ||
		strings.Contains(errStr, "login_buffer expired")
}

func isNonRetryableBizErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "wx.login returned empty code") ||
		strings.Contains(msg, "non-miniprogram AppID") ||
		strings.Contains(msg, "appid must be") ||
		strings.Contains(msg, "redirect_uri") ||
		strings.Contains(msg, "scope must be") ||
		strings.Contains(msg, "state is invalid") ||
		strings.Contains(msg, "h5 oauth:") ||
		strings.Contains(msg, "h5 a8key:") {
		return true
	}
	var h5Rej *protocol.ErrH5OAuthBusinessRejected
	var a8Rej *protocol.ErrH5A8KeyBusinessRejected
	if errors.As(err, &h5Rej) || errors.As(err, &a8Rej) {
		// oauth_authorize / ilinkgeta8key 已成功解密并返回明确业务拒绝码，说明底层会话本身存活；
		// 绝不因 H5 业务拒绝去消耗一次性 AutoAuth 密钥或清空缓存会话重建。
		return true
	}
	return false
}

// shouldRebuildSession distinguishes genuine WeChat session/decrypt invalidations
// from transient network/timeout blips so a brief timeout never burns a rotating
// AutoAuth key or deletes a healthy cached WMPF AppSession.
func shouldRebuildSession(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var slRej *protocol.ShortlinkRejectedError
	if errors.As(err, &slRej) {
		return true
	}
	var h5Rej *protocol.ErrH5OAuthBusinessRejected
	if errors.As(err, &h5Rej) {
		return !isNonRetryableBizErr(err)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "httpdns") {
		return false
	}
	return strings.Contains(msg, "appdata decrypt/parse failed") ||
		strings.Contains(msg, "response decrypt failed") ||
		strings.Contains(msg, "missing serverhello/appdata") ||
		strings.Contains(msg, "empty shortlink response") ||
		strings.Contains(msg, "did not contain application data")
}

// tryRefreshLoginBuffer attempts to obtain a fresh login_buffer from Tencent UAL
// when ManualAuth rejects the stored one: first via an unexpired access_token,
// then via RefreshCredentials (/pc_yyb/pcyyb_refresh_token + check_login) + FetchLoginBuffer.
// Rotated OAuth credentials are always persisted even if FetchLoginBuffer fails.
func (a *App) tryRefreshLoginBuffer(ctx context.Context, acc *store.WechatAccount) (bool, string) {
	if acc == nil || acc.Credentials == nil {
		return false, "no stored UAL credentials"
	}
	creds := protocol.CredentialsFromMap(acc.Credentials)
	refreshCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	var errs []string
	if creds.AccessToken != "" && !creds.Expired(2*time.Minute) {
		lb, err := a.qr.LoginBuffers().FetchLoginBuffer(refreshCtx, creds)
		if err == nil && lb != "" && lb != acc.LoginBuffer {
			acc.LoginBuffer = lb
			_ = a.db.SetAccountCredential(context.WithoutCancel(ctx), acc.ID, lb, creds.ToMap())
			log.Printf("[loginBufferRefresh] account %d (%s) fetched fresh login_buffer via active access_token", acc.ID, acc.OpenID)
			return true, ""
		}
		if err != nil {
			errs = append(errs, "fetch_login_buffer: "+err.Error())
		}
	}
	if creds.RefreshToken != "" {
		res, err := a.qr.RefreshLoginBuffer(refreshCtx, creds)
		if res.Refreshed && res.Credentials.AccessToken != "" {
			acc.Credentials = res.Credentials.ToMap()
			lb := acc.LoginBuffer
			if res.LoginBuffer != "" {
				lb = res.LoginBuffer
				acc.LoginBuffer = lb
			}
			_ = a.db.SetAccountCredential(context.WithoutCancel(ctx), acc.ID, lb, acc.Credentials)
			a.clearUALBackoff(acc.ID)
		}
		if err == nil && res.LoginBuffer != "" {
			log.Printf("[loginBufferRefresh] account %d (%s) refreshed login_buffer via UAL refresh_token", acc.ID, acc.OpenID)
			return true, ""
		}
		if err != nil {
			errs = append(errs, "ual_refresh: "+err.Error())
		}
	} else {
		errs = append(errs, "ual_refresh: missing refresh_token")
	}
	return false, strings.Join(errs, "; ")
}

func (a *App) retryWithFreshLoginBuffer(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, call wxappCall, origErr error, priorDiag ...string) (map[string]any, error) {
	refreshed, refreshReason := a.tryRefreshLoginBuffer(ctx, acc)
	if refreshed {
		_ = a.db.InvalidateAllSessions(ctx, acc.ID)
		result, retryErr := call(ctx, acc, appID, payload)
		if retryErr == nil {
			_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
			return result, nil
		}
		if !isLoginBufferExpiredErr(retryErr) {
			return nil, retryErr
		}
		origErr = retryErr
		refreshReason = "refreshed login_buffer still rejected"
	}
	var parts []string
	for _, d := range priorDiag {
		if d != "" {
			parts = append(parts, d)
		}
	}
	if origErr != nil {
		parts = append(parts, origErr.Error())
	}
	if refreshReason != "" {
		parts = append(parts, refreshReason)
	}
	detail := strings.Join(parts, "; ")
	log.Printf("[invokeWXApp] 账号 %d (%s) 微信凭据已失效: %s", acc.ID, acc.OpenID, detail)
	_ = a.db.SetAccountStatus(ctx, acc.ID, "expired")
	return nil, accountExpiredError{openid: acc.OpenID, detail: detail}
}

func (a *App) invokeWXApp(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any, call wxappCall) (map[string]any, error) {
	proxy := a.cfg.TCPProxy
	// Bound total per-request recovery budget so serial fallbacks never cascade
	// past reverse-proxy / client timeouts (preventing opaque gateway 502/504s).
	ctx, cancel := context.WithTimeout(ctx, 24*time.Second)
	defer cancel()

	// 1. 优先使用当前已缓存 session（外层 PSK 过期时 pool.state 会自动匿名续期 PSK 并保留 AppSession）
	result, err := call(ctx, acc, appID, payload)
	if err == nil {
		if acc.Status == nil || *acc.Status != "alive" {
			_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
		}
		return result, nil
	}
	if isNonRetryableBizErr(err) {
		return nil, err
	}
	if isLoginBufferExpiredErr(err) {
		return a.retryWithFreshLoginBuffer(ctx, acc, appID, payload, call, err)
	}
	if ctx.Err() != nil {
		return nil, err
	}

	firstDiag := err.Error()

	// 2. 若属于外层传输/PSK 异常（非明确业务码或 ShortLink 应用层拒绝），先尝试仅匿名刷新外层 MMTLS PSK
	var h5Rej *protocol.ErrH5OAuthBusinessRejected
	var slRej *protocol.ShortlinkRejectedError
	if !errors.As(err, &h5Rej) && !errors.As(err, &slRej) {
		if pskErr := a.pool.RefreshSessionPSK(ctx, acc.ID, proxy); pskErr == nil {
			log.Printf("[invokeWXApp] 账号 %d (%s) 调用失败(%v)，已匿名续期 MMTLS PSK 并重试", acc.ID, acc.OpenID, err)
			result, err = call(ctx, acc, appID, payload)
			if err == nil {
				_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
				return result, nil
			}
			if isNonRetryableBizErr(err) {
				return nil, err
			}
			if isLoginBufferExpiredErr(err) {
				return a.retryWithFreshLoginBuffer(ctx, acc, appID, payload, call, err, firstDiag)
			}
			firstDiag = err.Error()
		}
	}
	if ctx.Err() != nil || !shouldRebuildSession(err) {
		return nil, err
	}

	// 3. 会话在微信侧失效（如 shortlink_application -14 或会话超时）：
	//    在删除缓存会话前，优先尝试独立的微信原生 iLink AutoAuth (cmd 3198) 轮换密钥恢复（不依赖 OAuth/login_buffer）
	var autoAuthDiag string
	if autoErr := a.pool.TryNativeAutoAuth(ctx, acc.ID, proxy); autoErr == nil {
		log.Printf("[invokeWXApp] 账号 %d (%s) 原生 AutoAuth(3198) 密钥轮换成功，重试业务调用", acc.ID, acc.OpenID)
		result, err = call(ctx, acc, appID, payload)
		if err == nil {
			_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
			return result, nil
		}
		if isNonRetryableBizErr(err) {
			return nil, err
		}
		if isLoginBufferExpiredErr(err) {
			return a.retryWithFreshLoginBuffer(ctx, acc, appID, payload, call, err, firstDiag)
		}
		autoAuthDiag = "post_autoauth: " + err.Error()
	} else {
		autoAuthDiag = "autoauth: " + autoErr.Error()
		log.Printf("[invokeWXApp] 账号 %d (%s) 原生 AutoAuth 未恢复(%v)，回退 login_buffer 重建", acc.ID, acc.OpenID, autoErr)
	}
	if ctx.Err() != nil {
		return nil, err
	}

	// 4. 清理失效会话，使用 login_buffer 重建 WMPF 会话
	log.Printf("[invokeWXApp] 账号 %d (%s) 业务调用失败: %v，清理失效会话并尝试重建", acc.ID, acc.OpenID, err)
	_ = a.db.InvalidateAllSessions(ctx, acc.ID)

	result, err = call(ctx, acc, appID, payload)
	if err == nil {
		_ = a.db.SetAccountStatus(ctx, acc.ID, "alive")
		return result, nil
	}

	// 5. 重建时若 login_buffer 被拒绝，先尝试按需刷新 OAuth 凭据与 login_buffer 再判定 expired
	log.Printf("[invokeWXApp] 账号 %d (%s) 重建会话后依然失败: %v", acc.ID, acc.OpenID, err)
	if isLoginBufferExpiredErr(err) {
		return a.retryWithFreshLoginBuffer(ctx, acc, appID, payload, call, err, firstDiag, autoAuthDiag)
	}

	// 其它网络超时或短链接波动，不误改账号状态为 expired
	return nil, err
}

func (a *App) invokeGetCode(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	normID := strings.ToLower(strings.TrimSpace(appID))
	if label, denied := builtinNonMiniProgramAppIDs[normID]; denied {
		return nil, errors.New("non-miniprogram AppID denied for /wxapp/getCode (" + label + "); use /wx/h5code instead")
	}
	return a.pool.GetCode(ctx, acc.LoginBuffer, appID, acc.ID, a.cfg.TCPProxy)
}

func (a *App) invokeGetPhoneNumber(ctx context.Context, acc *store.WechatAccount, appID string, _ map[string]any) (map[string]any, error) {
	return a.pool.GetPhoneNumber(ctx, acc.LoginBuffer, appID, acc.ID, a.cfg.TCPProxy)
}

func (a *App) invokeOperateWXData(ctx context.Context, acc *store.WechatAccount, appID string, payload map[string]any) (map[string]any, error) {
	return a.pool.OperateWXData(ctx, acc.LoginBuffer, appID, payload, acc.ID, a.cfg.TCPProxy)
}

func refreshOut(acc *store.WechatAccount, status string) map[string]any {
	return map[string]any{"id": acc.ID, "openid": acc.OpenID, "uin": acc.UIN, "nickname": acc.Nickname, "status": status}
}

func pickNickname(userInfo map[string]any, fallback string) string {
	if s := stringFromAny(userInfo["nick_name"]); s != "" {
		return s
	}
	return fallback
}

func pickAvatarURL(userInfo map[string]any) string {
	for _, k := range []string{"head_img_url", "head_url", "headimgurl", "avatar"} {
		if s := stringFromAny(userInfo[k]); s != "" {
			return s
		}
	}
	return ""
}

func (a *App) resolveAvatar(ctx context.Context, openid string, userInfo map[string]any) string {
	u := pickAvatarURL(userInfo)
	if u == "" {
		return ""
	}
	dest := a.resources.avatarPath(openid)
	if downloadAvatar(ctx, u, dest, a.cfg.AvatarTimeout) {
		return dest
	}
	return u
}

func downloadAvatar(ctx context.Context, url, dest string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != 200 || !looksLikeImage(data) {
		return false
	}
	_ = os.MkdirAll(filepath.Dir(dest), 0o755)
	return os.WriteFile(dest, data, 0o644) == nil
}

func looksLikeImage(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	magics := [][]byte{{0xff, 0xd8, 0xff}, {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("GIF87a"), []byte("GIF89a")}
	for _, m := range magics {
		if strings.HasPrefix(string(data), string(m)) {
			return true
		}
	}
	return false
}

func (a *App) getQRSession(id string) *qr.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.qrSessions[id]
}

func (a *App) dropQRSession(id string) {
	a.mu.Lock()
	delete(a.qrSessions, id)
	a.mu.Unlock()
	_ = os.Remove(a.resources.qrPath(id))
}

func (a *App) pruneQR() {
	a.mu.Lock()
	var drop []string
	for sid, sess := range a.qrSessions {
		if sess.Age() > a.cfg.QRSessionTTL {
			drop = append(drop, sid)
		}
	}
	for _, sid := range drop {
		delete(a.qrSessions, sid)
	}
	a.mu.Unlock()
	for _, sid := range drop {
		_ = os.Remove(a.resources.qrPath(sid))
	}
}

func (a *App) cleanupQR(keep map[string]bool) {
	files, _ := filepath.Glob(filepath.Join(a.resources.QR, "*.jpg"))
	for _, f := range files {
		sid := strings.TrimSuffix(filepath.Base(f), ".jpg")
		if !keep[sid] {
			_ = os.Remove(f)
		}
	}
}

func terminalQR(status string) bool {
	return status == "expired" || status == "cancelled" || status == "unknown"
}

type apiEnvelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	writeRawJSON(w, status, apiEnvelope{
		Code: 0,
		Msg:  "success",
		Data: v,
	})
}

func writeRawJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeRawJSON(w, status, apiEnvelope{
		Code: status,
		Msg:  detail,
		Data: nil,
	})
}

func serveFileOrText(w http.ResponseWriter, r *http.Request, path, fallback string) {
	if _, err := os.Stat(path); err == nil {
		http.ServeFile(w, r, path)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fallback))
}

func stringFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringPtrMaybe(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── Web 管理 handler 函数 ─────────────────────────────────────────────

func (a *App) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]store.AccountPublic, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, acc.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Ref string `json:"ref"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Ref == "" {
		body.Ref = r.URL.Query().Get("ref")
	}
	if body.Ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required")
		return
	}
	acc, err := a.db.ResolveAccount(r.Context(), body.Ref)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found: "+body.Ref)
		return
	}
	if err := a.db.DeleteAccount(r.Context(), acc.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": acc.ID, "openid": acc.OpenID})
}

func (a *App) handleAdminRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, refreshOut(acc, a.refreshLiveness(r.Context(), acc)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleMyStatus(w http.ResponseWriter, r *http.Request) {
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
	adminCookie, _ := getCookie(r, "yyb_admin")
	isAdmin := adminCookie != "" && a.webAuth.IsValidAdmin(adminCookie)
	// Admin 扫码后优先返回当前 session 对应的 account，
	// 这样 user.html 能正常展示京东验证按钮等用户功能。
	if isAdmin {
		acc, err := a.db.GetAccount(r.Context(), sess.WechatAccountID)
		if err == nil && acc != nil {
			writeJSON(w, http.StatusOK, map[string]any{"is_admin": true, "account": acc.Public()})
			return
		}
		// fallback: 返回全部账号列表
		accounts, err := a.db.ListAccounts(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]store.AccountPublic, 0, len(accounts))
		for _, a := range accounts {
			out = append(out, a.Public())
		}
		writeJSON(w, http.StatusOK, map[string]any{"is_admin": true, "accounts": out})
		return
	}
	acc, err := a.db.GetAccount(r.Context(), sess.WechatAccountID)
	if err != nil {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"is_admin": false, "account": acc.Public()})
}

func getCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func (a *App) handleMyAvatar(w http.ResponseWriter, r *http.Request) {
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
	acc, err := a.db.GetAccount(r.Context(), sess.WechatAccountID)
	if err != nil || acc == nil {
		writeError(w, http.StatusNotFound, "账号不存在")
		return
	}
	a.serveAvatar(w, r, acc)
}

func sessionCookie(r *http.Request, name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
	}
}

func isHTTPSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
