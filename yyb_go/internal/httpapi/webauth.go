package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// WebSessionManager manages admin login sessions in memory with TTL.
type WebSessionManager struct {
	mu      sync.RWMutex
	admins  map[string]int64 // token -> expiresAt (unix seconds)
	webUser string
	webPass string
}

// NewWebSessionManager creates a manager with the given admin credentials.
func NewWebSessionManager(user, pass string) *WebSessionManager {
	return &WebSessionManager{
		admins:  make(map[string]int64),
		webUser: user,
		webPass: pass,
	}
}

// CheckAdminLogin validates username/password against env-configured credentials.
func (m *WebSessionManager) CheckAdminLogin(user, pass string) bool {
	if user == "" || pass == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user), []byte(m.webUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(m.webPass)) == 1
}

// CreateAdminSession generates a new admin session token.
func (m *WebSessionManager) CreateAdminSession(ttl time.Duration) (string, time.Time) {
	token := randomToken()
	expiry := time.Now().Add(ttl)
	m.mu.Lock()
	m.admins[token] = expiry.Unix()
	m.mu.Unlock()
	return token, expiry
}

// IsValidAdmin checks if a token is a valid, non-expired admin session.
func (m *WebSessionManager) IsValidAdmin(token string) bool {
	if token == "" {
		return false
	}
	m.mu.RLock()
	exp, ok := m.admins[token]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().Unix() > exp {
		m.mu.Lock()
		delete(m.admins, token)
		m.mu.Unlock()
		return false
	}
	return true
}

// DestroyAdminSession removes an admin session.
func (m *WebSessionManager) DestroyAdminSession(token string) {
	m.mu.Lock()
	delete(m.admins, token)
	m.mu.Unlock()
}

// RequireAdminAuth middleware: allows if a valid admin session cookie is present,
// or if the request carries a valid Bearer API token (existing auth path).
func (a *App) RequireAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Existing API token path still works
		if a.cfg.APIToken != "" {
			auth := c.GetHeader("Authorization")
			if strings.HasPrefix(auth, "Bearer ") && subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(a.cfg.APIToken)) == 1 {
				c.Next()
				return
			}
		}
		// Admin web session path
		cookie, err := c.Cookie("yyb_admin")
		if err == nil && a.webAuth.IsValidAdmin(cookie) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthorized", "data": nil})
	}
}

// RequireUserAuth middleware: allows if a valid user session cookie is present
// (backed by DB user_sessions table) OR if admin session is present.
func (a *App) RequireUserAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Admin can always access user routes
		cookie, err := c.Cookie("yyb_admin")
		if err == nil && a.webAuth.IsValidAdmin(cookie) {
			c.Set("is_admin", true)
			c.Next()
			return
		}
		// User session via DB
		userCookie, err := c.Cookie("yyb_user")
		if err == nil && userCookie != "" {
			sess, err := a.db.GetUserSession(c.Request.Context(), userCookie)
			if err == nil && sess != nil {
				c.Set("user_account_id", sess.WechatAccountID)
				c.Set("is_admin", false)
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "unauthorized", "data": nil})
	}
}

// randomToken generates a 32-byte hex token using crypto/rand.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
