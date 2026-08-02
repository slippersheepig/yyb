package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS wechat_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    openid          TEXT    NOT NULL UNIQUE,
    uin             INTEGER,
    alias           TEXT,
    nickname        TEXT,
    avatar          TEXT,
    user_info       TEXT,
    login_buffer    TEXT    NOT NULL,
    credentials     TEXT,
    status          TEXT,
    jd_risk_url     TEXT,
    jd_cookie        TEXT,
    last_checked_at INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wxacc_uin ON wechat_accounts(uin);

CREATE TABLE IF NOT EXISTS sessions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wechat_account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
    uin               INTEGER,
    tcp_proxy         TEXT    NOT NULL DEFAULT '',
    session_blob      TEXT    NOT NULL,
    expires_at        INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE(wechat_account_id, tcp_proxy)
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_token TEXT NOT NULL UNIQUE,
    wechat_account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);

CREATE TABLE IF NOT EXISTS features (
    code        INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS wx_bindings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wechat_account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
    bind_code         TEXT    NOT NULL UNIQUE,
    gzh_openid        TEXT,
    created_at        INTEGER NOT NULL,
    bound_at          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_wxbind_code ON wx_bindings(bind_code);
CREATE INDEX IF NOT EXISTS idx_wxbind_uid ON wx_bindings(gzh_openid);
CREATE INDEX IF NOT EXISTS idx_wxbind_acc ON wx_bindings(wechat_account_id);

CREATE TABLE IF NOT EXISTS wx_messages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wechat_account_id INTEGER NOT NULL REFERENCES wechat_accounts(id) ON DELETE CASCADE,
    msg_type          TEXT    NOT NULL,
    content           TEXT    NOT NULL,
    is_read           INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wxmsg_acc ON wx_messages(wechat_account_id, is_read);
`

var defaultFeatures = []Feature{
	{Code: 1001, Name: "getCode", Description: stringPtr("wx.login code"), Enabled: true},
	{Code: 1002, Name: "getPhoneNumber", Description: stringPtr("取手机号"), Enabled: true},
	{Code: 1003, Name: "operateWxData", Description: stringPtr("通用云函数代理"), Enabled: true},
}

type DB struct {
	sql *sql.DB
}

type WechatAccount struct {
	ID            int64          `json:"id"`
	OpenID        string         `json:"openid"`
	UIN           *int64         `json:"uin,omitempty"`
	Alias         *string        `json:"alias,omitempty"`
	Nickname      *string        `json:"nickname,omitempty"`
	Avatar        *string        `json:"avatar,omitempty"`
	UserInfo      map[string]any `json:"user_info,omitempty"`
	LoginBuffer   string         `json:"login_buffer,omitempty"`
	Credentials   map[string]any `json:"credentials,omitempty"`
	Status        *string        `json:"status,omitempty"`
	JdRiskURL     *string        `json:"jd_risk_url,omitempty"`
	JdCookie      *string        `json:"jd_cookie,omitempty"`
	LastCheckedAt *int64         `json:"last_checked_at,omitempty"`
	CreatedAt     int64          `json:"created_at"`
	UpdatedAt     int64          `json:"updated_at"`
}

type AccountPublic struct {
	ID            int64   `json:"id"`
	OpenID        string  `json:"openid"`
	UIN           *int64  `json:"uin"`
	Alias         *string `json:"alias"`
	Nickname      *string `json:"nickname"`
	Avatar        *string `json:"avatar"`
	Status        *string `json:"status"`
	JdRiskURL     *string `json:"jd_risk_url,omitempty"`
	JdCookie      *string `json:"jd_cookie,omitempty"`
	LastCheckedAt *int64  `json:"last_checked_at"`
	CreatedAt     int64   `json:"created_at"`
	UpdatedAt     int64   `json:"updated_at"`
}

type SessionRow struct {
	ID              int64
	WechatAccountID int64
	UIN             *int64
	TCPProxy        string
	SessionBlob     map[string]any
	ExpiresAt       int64
	CreatedAt       int64
	UpdatedAt       int64
}

type Feature struct {
	Code        int     `json:"code"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Enabled     bool    `json:"enabled"`
}

type UserSession struct {
	SessionToken    string `json:"session_token"`
	WechatAccountID int64  `json:"wechat_account_id"`
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

type WxBinding struct {
	ID              int64   `json:"id"`
	WechatAccountID int64   `json:"wechat_account_id"`
	BindCode        string  `json:"bind_code"`
	GzhOpenID       *string `json:"gzh_openid,omitempty"`
	CreatedAt       int64   `json:"created_at"`
	BoundAt         *int64  `json:"bound_at,omitempty"`
}

type WxMessage struct {
	ID              int64  `json:"id"`
	WechatAccountID int64  `json:"wechat_account_id"`
	MsgType         string `json:"msg_type"`
	Content         string `json:"content"`
	IsRead          bool   `json:"is_read"`
	CreatedAt       int64  `json:"created_at"`
}

func Open(path string) (*DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" {
		_, _ = db.ExecContext(ctx, "PRAGMA journal_mode=WAL")
	}
	_, _ = db.ExecContext(ctx, "PRAGMA synchronous=NORMAL")
	if _, err = db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = migrateSessionsTable(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = migrateJdRiskURLColumn(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = migrateJdCookieColumn(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err = db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	out := &DB{sql: db}
	if err = out.EnsureDefaultFeatures(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return out, nil
}

func (db *DB) CreateUserSession(ctx context.Context, accountID int64, ttl time.Duration) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	expiresAt := now + int64(ttl.Seconds())
	_, err = db.sql.ExecContext(ctx,
		"INSERT INTO user_sessions(session_token, wechat_account_id, created_at, expires_at) VALUES(?,?,?,?)",
		token, accountID, now, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (db *DB) GetUserSession(ctx context.Context, token string) (*UserSession, error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT session_token, wechat_account_id, created_at, expires_at FROM user_sessions WHERE session_token=? AND expires_at>?",
		token, time.Now().Unix(),
	)
	var s UserSession
	if err := row.Scan(&s.SessionToken, &s.WechatAccountID, &s.CreatedAt, &s.ExpiresAt); err != nil {
		return nil, err
	}
	return &s, nil
}

func (db *DB) DeleteUserSession(ctx context.Context, token string) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM user_sessions WHERE session_token=?", token)
	return err
}

func (db *DB) PurgeExpiredUserSessions(ctx context.Context) (int64, error) {
	res, err := db.sql.ExecContext(ctx, "DELETE FROM user_sessions WHERE expires_at<=?", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	return db.sql.Close()
}

func (db *DB) EnsureDefaultFeatures(ctx context.Context) error {
	for _, f := range defaultFeatures {
		desc := nullableString(f.Description)
		if _, err := db.sql.ExecContext(ctx,
			"INSERT OR IGNORE INTO features(code, name, description, enabled) VALUES(?,?,?,1)",
			f.Code, f.Name, desc,
		); err != nil {
			return err
		}
	}
	return nil
}

// migrateJdRiskURLColumn adds the jd_risk_url column to existing wechat_accounts tables
// that were created before this feature was introduced.
func migrateJdRiskURLColumn(ctx context.Context, db *sql.DB) error {
	// Check if the column already exists.
	var colCount int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('wechat_accounts') WHERE name='jd_risk_url'`,
	).Scan(&colCount); err != nil {
		return fmt.Errorf("check jd_risk_url column: %w", err)
	}
	if colCount > 0 {
		return nil // already migrated
	}
	_, err := db.ExecContext(ctx, `ALTER TABLE wechat_accounts ADD COLUMN jd_risk_url TEXT`)
	if err != nil {
		return fmt.Errorf("add jd_risk_url column: %w", err)
	}
	log.Printf("[migration] added jd_risk_url column to wechat_accounts")
	return nil
}

// migrateJdCookieColumn adds the jd_cookie column to existing wechat_accounts tables
// that were created before this feature was introduced.
func migrateJdCookieColumn(ctx context.Context, db *sql.DB) error {
	var colCount int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('wechat_accounts') WHERE name='jd_cookie'`,
	).Scan(&colCount); err != nil {
		return fmt.Errorf("check jd_cookie column: %w", err)
	}
	if colCount > 0 {
		return nil // already migrated
	}
	_, err := db.ExecContext(ctx, `ALTER TABLE wechat_accounts ADD COLUMN jd_cookie TEXT`)
	if err != nil {
		return fmt.Errorf("add jd_cookie column: %w", err)
	}
	log.Printf("[migration] added jd_cookie column to wechat_accounts")
	return nil
}

func migrateSessionsTable(ctx context.Context, db *sql.DB) error {
	oldExists, err := sqliteTableExists(ctx, db, "wmpf_sessions")
	if err != nil {
		return err
	}
	if !oldExists {
		return nil
	}
	newExists, err := sqliteTableExists(ctx, db, "sessions")
	if err != nil {
		return err
	}
	if !newExists {
		if _, err = db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_sess_expires"); err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, "ALTER TABLE wmpf_sessions RENAME TO sessions")
		return err
	}
	if _, err = db.ExecContext(ctx, `
INSERT OR IGNORE INTO sessions
(id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at)
SELECT id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at
FROM wmpf_sessions`); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "DROP TABLE wmpf_sessions")
	return err
}

func sqliteTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0, err
}

func (db *DB) UpsertAccount(ctx context.Context, openid, loginBuffer string, alias, nickname, avatar *string, userInfo map[string]any, credentials map[string]any, status *string) (*WechatAccount, error) {
	now := time.Now().Unix()
	userJSON, err := marshalNullable(userInfo)
	if err != nil {
		return nil, err
	}
	credJSON, err := marshalNullable(credentials)
	if err != nil {
		return nil, err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO wechat_accounts
		(openid, login_buffer, alias, nickname, avatar, user_info, credentials, status, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(openid) DO UPDATE SET
		login_buffer=excluded.login_buffer, alias=excluded.alias, nickname=excluded.nickname,
		avatar=excluded.avatar, user_info=excluded.user_info, credentials=excluded.credentials,
		status=excluded.status, updated_at=excluded.updated_at`,
		openid, loginBuffer, nullableString(alias), nullableString(nickname), nullableString(avatar),
		userJSON, credJSON, nullableString(status), now, now,
	)
	if err != nil {
		return nil, err
	}
	return db.GetAccountByOpenID(ctx, openid)
}

func (db *DB) GetAccount(ctx context.Context, id int64) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE id=?", id))
}

func (db *DB) GetAccountByOpenID(ctx context.Context, openid string) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE openid=?", openid))
}

func (db *DB) GetAccountByUIN(ctx context.Context, uin int64) (*WechatAccount, error) {
	return db.scanAccount(db.sql.QueryRowContext(ctx, selectAccountSQL+" WHERE uin=?", uin))
}

func (db *DB) ResolveAccount(ctx context.Context, ref string) (*WechatAccount, error) {
	if ref == "" {
		return nil, sql.ErrNoRows
	}
	if isDigits(ref) {
		n, _ := strconv.ParseInt(ref, 10, 64)
		if acc, err := db.GetAccountByUIN(ctx, n); err == nil {
			return acc, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return db.GetAccount(ctx, n)
	}
	return db.GetAccountByOpenID(ctx, ref)
}

func (db *DB) ListAccounts(ctx context.Context) ([]*WechatAccount, error) {
	rows, err := db.sql.QueryContext(ctx, selectAccountSQL+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WechatAccount
	for rows.Next() {
		acc, err := scanAccountRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, rows.Err()
}

func (db *DB) SetAccountUIN(ctx context.Context, id, uin int64) error {
	_, err := db.sql.ExecContext(ctx, "UPDATE wechat_accounts SET uin=?, updated_at=? WHERE id=?", uin, time.Now().Unix(), id)
	return err
}

func (db *DB) SetAccountProfile(ctx context.Context, id int64, nickname, avatar *string, userInfo map[string]any) error {
	userJSON, err := marshalNullable(userInfo)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET nickname=?, avatar=?, user_info=?, updated_at=? WHERE id=?",
		nullableString(nickname), nullableString(avatar), userJSON, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) SetAccountCredential(ctx context.Context, id int64, loginBuffer string, credentials map[string]any) error {
	credJSON, err := marshalNullable(credentials)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET login_buffer=?, credentials=?, updated_at=? WHERE id=?",
		loginBuffer, credJSON, time.Now().Unix(), id,
	)
	return err
}

func (db *DB) SetAccountStatus(ctx context.Context, id int64, status string) error {
	now := time.Now().Unix()
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET status=?, last_checked_at=?, updated_at=? WHERE id=?",
		status, now, now, id,
	)
	return err
}

// SetJdRiskURL stores or clears the JD risk verification URL for an account.
func (db *DB) SetJdRiskURL(ctx context.Context, id int64, riskURL string) error {
	now := time.Now().Unix()
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET jd_risk_url=?, updated_at=? WHERE id=?",
		riskURL, now, id,
	)
	return err
}

// SetJdCookie stores the assembled JD cookie string for an account.
func (db *DB) SetJdCookie(ctx context.Context, id int64, ck string) error {
	now := time.Now().Unix()
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wechat_accounts SET jd_cookie=?, updated_at=? WHERE id=?",
		ck, now, id,
	)
	return err
}

func (db *DB) DeleteAccount(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM wechat_accounts WHERE id=?", id)
	return err
}

func (db *DB) GetSession(ctx context.Context, accountID int64, tcpProxy string) (*SessionRow, error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT id, wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at FROM sessions WHERE wechat_account_id=? AND tcp_proxy=? AND expires_at>?",
		accountID, tcpProxy, time.Now().Unix(),
	)
	return scanSession(row)
}

func (db *DB) PutSession(ctx context.Context, accountID int64, uin *int64, sessionBlob map[string]any, expiresAt int64, tcpProxy string) error {
	now := time.Now().Unix()
	blob, err := json.Marshal(sessionBlob)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO sessions
		(wechat_account_id, uin, tcp_proxy, session_blob, expires_at, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(wechat_account_id, tcp_proxy) DO UPDATE SET
		uin=excluded.uin, session_blob=excluded.session_blob,
		expires_at=excluded.expires_at, updated_at=excluded.updated_at`,
		accountID, nullableInt(uin), tcpProxy, string(blob), expiresAt, now, now,
	)
	return err
}

func (db *DB) InvalidateSession(ctx context.Context, accountID int64, tcpProxy string) error {
	_, err := db.sql.ExecContext(ctx, "DELETE FROM sessions WHERE wechat_account_id=? AND tcp_proxy=?", accountID, tcpProxy)
	return err
}

func (db *DB) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := db.sql.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) ListFeatures(ctx context.Context, onlyEnabled bool) ([]Feature, error) {
	sqlText := "SELECT code, name, description, enabled FROM features"
	if onlyEnabled {
		sqlText += " WHERE enabled=1"
	}
	sqlText += " ORDER BY code"
	rows, err := db.sql.QueryContext(ctx, sqlText)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Feature
	for rows.Next() {
		f, err := scanFeature(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) ResolveFeature(ctx context.Context, ref any) (*Feature, error) {
	switch v := ref.(type) {
	case float64:
		return db.GetFeature(ctx, int(v))
	case int:
		return db.GetFeature(ctx, v)
	case string:
		if isDigits(v) {
			n, _ := strconv.Atoi(v)
			return db.GetFeature(ctx, n)
		}
		return db.GetFeatureByName(ctx, v)
	default:
		return nil, sql.ErrNoRows
	}
}

func (db *DB) GetFeature(ctx context.Context, code int) (*Feature, error) {
	row := db.sql.QueryRowContext(ctx, "SELECT code, name, description, enabled FROM features WHERE code=?", code)
	f, err := scanFeature(row)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (db *DB) GetFeatureByName(ctx context.Context, name string) (*Feature, error) {
	row := db.sql.QueryRowContext(ctx, "SELECT code, name, description, enabled FROM features WHERE name=? COLLATE NOCASE", name)
	f, err := scanFeature(row)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (a *WechatAccount) Public() AccountPublic {
	return AccountPublic{
		ID:            a.ID,
		OpenID:        a.OpenID,
		UIN:           a.UIN,
		Alias:         a.Alias,
		Nickname:      a.Nickname,
		Avatar:        a.Avatar,
		Status:        a.Status,
		JdRiskURL:     a.JdRiskURL,
		JdCookie:      a.JdCookie,
		LastCheckedAt: a.LastCheckedAt,
		CreatedAt:     a.CreatedAt,
		UpdatedAt:     a.UpdatedAt,
	}
}

const selectAccountSQL = `SELECT id, openid, uin, alias, nickname, avatar, user_info, login_buffer, credentials, status, jd_risk_url, jd_cookie, last_checked_at, created_at, updated_at FROM wechat_accounts`

type accountScanner interface {
	Scan(dest ...any) error
}

type featureScanner interface {
	Scan(dest ...any) error
}

func (db *DB) scanAccount(row accountScanner) (*WechatAccount, error) {
	return scanAccountRows(row)
}

func scanAccountRows(row accountScanner) (*WechatAccount, error) {
	var (
		a                       WechatAccount
		uin, lastChecked        sql.NullInt64
		alias, nickname, avatar sql.NullString
		userJSON, credJSON      sql.NullString
		status, jdRiskURL       sql.NullString
		jdCookie                sql.NullString
	)
	err := row.Scan(
		&a.ID, &a.OpenID, &uin, &alias, &nickname, &avatar, &userJSON,
		&a.LoginBuffer, &credJSON, &status, &jdRiskURL, &jdCookie, &lastChecked, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if uin.Valid {
		a.UIN = &uin.Int64
	}
	a.Alias = stringPtrFromNull(alias)
	a.Nickname = stringPtrFromNull(nickname)
	a.Avatar = stringPtrFromNull(avatar)
	a.Status = stringPtrFromNull(status)
	a.JdRiskURL = stringPtrFromNull(jdRiskURL)
	a.JdCookie = stringPtrFromNull(jdCookie)
	if lastChecked.Valid {
		a.LastCheckedAt = &lastChecked.Int64
	}
	if userJSON.Valid && userJSON.String != "" {
		_ = json.Unmarshal([]byte(userJSON.String), &a.UserInfo)
	}
	if credJSON.Valid && credJSON.String != "" {
		_ = json.Unmarshal([]byte(credJSON.String), &a.Credentials)
	}
	return &a, nil
}

func scanSession(row accountScanner) (*SessionRow, error) {
	var s SessionRow
	var uin sql.NullInt64
	var blob string
	if err := row.Scan(&s.ID, &s.WechatAccountID, &uin, &s.TCPProxy, &blob, &s.ExpiresAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	if uin.Valid {
		s.UIN = &uin.Int64
	}
	if err := json.Unmarshal([]byte(blob), &s.SessionBlob); err != nil {
		return nil, fmt.Errorf("decode session_blob: %w", err)
	}
	return &s, nil
}

func scanFeature(row featureScanner) (Feature, error) {
	var f Feature
	var desc sql.NullString
	var enabled int
	if err := row.Scan(&f.Code, &f.Name, &desc, &enabled); err != nil {
		return Feature{}, err
	}
	f.Description = stringPtrFromNull(desc)
	f.Enabled = enabled != 0
	return f, nil
}

func marshalNullable(v map[string]any) (sql.NullString, error) {
	if v == nil {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func nullableString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullableInt(v *int64) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}

func stringPtrFromNull(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func stringPtr(s string) *string { return &s }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CreateBindCode generates a unique 6-digit numeric bind code for a yyb account.
// If an unbound code already exists for this account, it reuses it.
func (db *DB) CreateBindCode(ctx context.Context, accountID int64) (string, error) {
	var existing sql.NullString
	err := db.sql.QueryRowContext(ctx,
		"SELECT bind_code FROM wx_bindings WHERE wechat_account_id=? AND gzh_openid IS NULL ORDER BY created_at DESC LIMIT 1",
		accountID,
	).Scan(&existing)
	if err == nil && existing.Valid {
		return existing.String, nil
	}
	for i := 0; i < 10; i++ {
		code := randomBindCode()
		_, err := db.sql.ExecContext(ctx,
			"INSERT INTO wx_bindings(wechat_account_id, bind_code, created_at) VALUES(?,?,?)",
			accountID, code, time.Now().Unix(),
		)
		if err == nil {
			return code, nil
		}
		// Retry on duplicate (SQLite constraint code 19).
		var sqliteErr interface{ ErrorCode() int }
		if errors.As(err, &sqliteErr) && sqliteErr.ErrorCode() == 19 {
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("failed to generate unique bind code")
}

// BindWxUser binds a gzh openid to a yyb account via bind code.
func (db *DB) BindWxUser(ctx context.Context, bindCode, gzhOpenID string) (int64, error) {
	res, err := db.sql.ExecContext(ctx,
		"UPDATE wx_bindings SET gzh_openid=?, bound_at=? WHERE bind_code=? AND gzh_openid IS NULL",
		gzhOpenID, time.Now().Unix(), bindCode,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, fmt.Errorf("无效的绑定码或已绑定")
	}
	var accID int64
	err = db.sql.QueryRowContext(ctx,
		"SELECT wechat_account_id FROM wx_bindings WHERE bind_code=?", bindCode,
	).Scan(&accID)
	return accID, err
}

// GetAccountByGzhOpenID looks up a yyb account by gzh openid.
func (db *DB) GetAccountByGzhOpenID(ctx context.Context, gzhOpenID string) (*WechatAccount, error) {
	row := db.sql.QueryRowContext(ctx,
		selectAccountSQL+` WHERE id=(SELECT wechat_account_id FROM wx_bindings WHERE gzh_openid=? ORDER BY bound_at DESC LIMIT 1)`,
		gzhOpenID,
	)
	return db.scanAccount(row)
}

// GetBindCodeStatus returns the latest bind code for an account and whether it is bound.
func (db *DB) GetBindCodeStatus(ctx context.Context, accountID int64) (bindCode string, gzhOpenID *string, err error) {
	row := db.sql.QueryRowContext(ctx,
		"SELECT bind_code, gzh_openid FROM wx_bindings WHERE wechat_account_id=? ORDER BY created_at DESC LIMIT 1",
		accountID,
	)
	var gzh sql.NullString
	if err := row.Scan(&bindCode, &gzh); err != nil {
		return "", nil, err
	}
	if gzh.Valid {
		gzhOpenID = &gzh.String
	}
	return bindCode, gzhOpenID, nil
}

// PushWxMessage adds a message to the wx_messages pool.
func (db *DB) PushWxMessage(ctx context.Context, accountID int64, msgType, content string) (*WxMessage, error) {
	res, err := db.sql.ExecContext(ctx,
		"INSERT INTO wx_messages(wechat_account_id, msg_type, content, is_read, created_at) VALUES(?,?,?,0,?)",
		accountID, msgType, content, time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &WxMessage{
		ID: id, WechatAccountID: accountID, MsgType: msgType,
		Content: content, CreatedAt: time.Now().Unix(),
	}, nil
}

// FetchPendingMessages returns all unread messages for an account.
func (db *DB) FetchPendingMessages(ctx context.Context, accountID int64) ([]WxMessage, error) {
	rows, err := db.sql.QueryContext(ctx,
		"SELECT id, wechat_account_id, msg_type, content, is_read, created_at FROM wx_messages WHERE wechat_account_id=? AND is_read=0 ORDER BY id ASC",
		accountID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WxMessage
	for rows.Next() {
		var m WxMessage
		var isRead int64
		if err := rows.Scan(&m.ID, &m.WechatAccountID, &m.MsgType, &m.Content, &isRead, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.IsRead = isRead != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkMessagesRead marks all unread messages for an account as read.
func (db *DB) MarkMessagesRead(ctx context.Context, accountID int64) error {
	_, err := db.sql.ExecContext(ctx,
		"UPDATE wx_messages SET is_read=1 WHERE wechat_account_id=? AND is_read=0",
		accountID,
	)
	return err
}

func randomBindCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%900000+100000)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}
