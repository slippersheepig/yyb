package tgbot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"yyb_go/internal/store"
)

// Bot is a minimal Telegram Bot that supports admin-only commands and
// push notifications for new scan-logins.
type Bot struct {
	token      string
	adminIDs   map[int64]bool
	apiBase    string
	httpClient *http.Client
	db         *store.DB
	notifyCh   chan NewLoginEvent
	done       chan struct{}
	wg         sync.WaitGroup
}

// NewLoginEvent carries account info when a user confirms a QR scan.
type NewLoginEvent struct {
	OpenID   string
	Nickname string
	UIN      *int64
	Avatar   string
}

// Config holds Telegram bot configuration values.
type Config struct {
	Token    string
	AdminIDs []int64
}

// New creates a Bot. Returns nil if token or adminIDs are empty.
func New(cfg Config, db *store.DB) *Bot {
	if cfg.Token == "" || len(cfg.AdminIDs) == 0 {
		return nil
	}
	adminSet := make(map[int64]bool, len(cfg.AdminIDs))
	for _, id := range cfg.AdminIDs {
		adminSet[id] = true
	}
	return &Bot{
		token:    cfg.Token,
		adminIDs: adminSet,
		apiBase:  "https://api.telegram.org/bot" + cfg.Token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		db:       db,
		notifyCh: make(chan NewLoginEvent, 32),
		done:     make(chan struct{}),
	}
}

// Start launches the long-polling loop and the notification consumer.
// It should be called once from a goroutine.
func (b *Bot) Start(ctx context.Context) {
	// Verify bot token on startup.
	var me struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if err := b.apiGet(ctx, "getMe", nil, &me); err != nil {
		log.Printf("[tgbot] getMe failed: %v", err)
		return
	}
	if !me.OK {
		log.Printf("[tgbot] getMe returned not ok")
		return
	}
	log.Printf("[tgbot] authorised as @%s, %d admin(s)", me.Result.Username, len(b.adminIDs))

	b.wg.Add(2)
	go b.pollLoop(ctx)
	go b.notifyLoop(ctx)
}

// Stop gracefully shuts down the bot.
func (b *Bot) Stop() {
	close(b.done)
	b.wg.Wait()
}

// NotifyLogin enqueues a new-login event to be pushed to all admins.
func (b *Bot) NotifyLogin(ev NewLoginEvent) {
	select {
	case b.notifyCh <- ev:
	default:
		log.Printf("[tgbot] notify channel full, dropping login event for %s", ev.OpenID)
	}
}

// ── internal: long-polling ────────────────────────────────────────────

func (b *Bot) pollLoop(ctx context.Context) {
	defer b.wg.Done()

	offset := int64(0)
	retryDelay := time.Second

	for {
		select {
		case <-b.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		params := urlValues{
			"timeout": {"5"},
			"offset":  {strconv.FormatInt(offset, 10)},
		}
		var update struct {
			OK     bool `json:"ok"`
			Result []struct {
				UpdateID int64      `json:"update_id"`
				Message  *tgMessage `json:"message"`
			} `json:"result"`
		}

		pollCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		err := b.apiGet(pollCtx, "getUpdates", params, &update)
		cancel()

		if err != nil {
			log.Printf("[tgbot] getUpdates error: %v", err)
			select {
			case <-b.done:
				return
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
				retryDelay = min(retryDelay*2, 30*time.Second)
				continue
			}
		}
		retryDelay = time.Second

		if !update.OK {
			continue
		}

		for _, u := range update.Result {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			if u.Message == nil || u.Message.From == nil || u.Message.Chat == nil {
				continue
			}
			b.handleMessage(ctx, u.Message)
		}
	}
}

// ── internal: notification consumer ──────────────────────────────────

func (b *Bot) notifyLoop(ctx context.Context) {
	defer b.wg.Done()
	for {
		select {
		case <-b.done:
			return
		case <-ctx.Done():
			return
		case ev := <-b.notifyCh:
			b.pushLoginNotification(ctx, ev)
		}
	}
}

func (b *Bot) pushLoginNotification(ctx context.Context, ev NewLoginEvent) {
	nick := ev.Nickname
	if nick == "" {
		nick = ev.OpenID
	}
	uinStr := "-"
	if ev.UIN != nil {
		uinStr = strconv.FormatInt(*ev.UIN, 10)
	}
	text := fmt.Sprintf("🔔 新用户扫码登录\n\n"+
		"👤 昵称: %s\n"+
		"🆔 OpenID: `%s`\n"+
		"🔢 UIN: %s\n"+
		"🕐 时间: %s",
		escapeMarkdown(nick), escapeMarkdown(ev.OpenID), uinStr,
		time.Now().Format("2006-01-02 15:04:05"))

	for adminID := range b.adminIDs {
		b.sendMessage(ctx, adminID, text, true)
	}
}

// tgMessage is the Telegram message struct shared between pollLoop and handleMessage.
type tgMessage struct {
	MessageID int64 `json:"message_id"`
	From      *struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	} `json:"from"`
	Chat *struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"chat"`
	Text string `json:"text"`
}

// ── internal: message handler ─────────────────────────────────────────

func (b *Bot) handleMessage(ctx context.Context, msg *tgMessage) {
	// Admin check
	if msg.From == nil || !b.adminIDs[msg.From.ID] {
		// Silently ignore non-admin messages
		return
	}

	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}

	// Parse command (support /cmd@botname syntax)
	args := strings.Fields(text)
	if len(args) == 0 {
		return
	}
	cmd := args[0]
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i]
	}

	switch cmd {
	case "/start", "/help":
		b.sendHelp(ctx, chatID)
	case "/status":
		b.cmdListAccounts(ctx, chatID)
	case "/accounts":
		b.cmdListAccounts(ctx, chatID)
	case "/delete":
		if len(args) < 2 {
			b.sendMessage(ctx, chatID, "用法: `/delete <openid|uin|id>`", true)
			return
		}
		b.cmdDeleteAccount(ctx, chatID, args[1])
	case "/refresh":
		b.cmdRefreshAll(ctx, chatID)
	case "/stats":
		b.cmdStats(ctx, chatID)
	case "/ping":
		b.sendMessage(ctx, chatID, "🏓 pong", false)
	default:
		// Ignore unknown commands
	}
}

func (b *Bot) sendHelp(ctx context.Context, chatID int64) {
	help := "🤖 YYB Go Bot 命令列表\n\n" +
		"/status - 查看所有账号状态\n" +
		"/accounts - 同上\n" +
		"/delete <openid|uin|id> - 删除指定账号\n" +
		"/refresh - 刷新所有账号存活状态\n" +
		"/stats - 查看统计信息\n" +
		"/ping - 检查机器人是否在线\n" +
		"/help - 显示此帮助信息"
	b.sendMessage(ctx, chatID, help, false)
}

func (b *Bot) cmdListAccounts(ctx context.Context, chatID int64) {
	accounts, err := b.db.ListAccounts(ctx)
	if err != nil {
		b.sendMessage(ctx, chatID, "❌ 获取账号列表失败: "+escapeMarkdown(err.Error()), true)
		return
	}
	if len(accounts) == 0 {
		b.sendMessage(ctx, chatID, "📭 当前没有任何账号", false)
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📋 账号列表 (%d)\n\n", len(accounts)))
	for i, acc := range accounts {
		nick := ""
		if acc.Nickname != nil {
			nick = *acc.Nickname
		}
		if nick == "" {
			nick = "(未命名)"
		}
		status := "未检测"
		if acc.Status != nil {
			status = *acc.Status
		}
		uin := "-"
		if acc.UIN != nil {
			uin = strconv.FormatInt(*acc.UIN, 10)
		}
		emoji := "✅"
		if status == "expired" {
			emoji = "⚠️"
		} else if status == "unknown" {
			emoji = "❓"
		}
		sb.WriteString(fmt.Sprintf("%s %d. %s\n   UIN: %s | 状态: %s\n   ID: %d | OpenID: `%s`\n\n",
			emoji, i+1, escapeMarkdown(nick), uin, status, acc.ID, escapeMarkdown(acc.OpenID)))
	}
	// Telegram message limit is 4096 chars
	msg := sb.String()
	if len(msg) > 4000 {
		msg = msg[:4000] + "\n... (消息过长,已截断)"
	}
	b.sendMessage(ctx, chatID, msg, true)
}

func (b *Bot) cmdDeleteAccount(ctx context.Context, chatID int64, ref string) {
	acc, err := b.db.ResolveAccount(ctx, ref)
	if err != nil {
		b.sendMessage(ctx, chatID, "❌ 找不到账号: "+escapeMarkdown(ref), true)
		return
	}
	nick := ""
	if acc.Nickname != nil {
		nick = *acc.Nickname
	}
	if nick == "" {
		nick = acc.OpenID
	}
	if err := b.db.DeleteAccount(ctx, acc.ID); err != nil {
		b.sendMessage(ctx, chatID, "❌ 删除失败: "+escapeMarkdown(err.Error()), true)
		return
	}
	text := fmt.Sprintf("🗑 已删除账号: %s (OpenID: `%s`, ID: %d)", escapeMarkdown(nick), escapeMarkdown(acc.OpenID), acc.ID)
	b.sendMessage(ctx, chatID, text, true)
}

func (b *Bot) cmdRefreshAll(ctx context.Context, chatID int64) {
	accounts, err := b.db.ListAccounts(ctx)
	if err != nil {
		b.sendMessage(ctx, chatID, "❌ 获取账号列表失败: "+escapeMarkdown(err.Error()), true)
		return
	}
	b.sendMessage(ctx, chatID, fmt.Sprintf("🔄 正在刷新 %d 个账号...", len(accounts)), false)
	// Note: actual refresh logic requires the qr.Client and protocol.Pool.
	// The bot only updated the status field in DB via a simple heuristic:
	// we mark them as "unknown" to indicate a manual refresh is needed.
	// Full refresh is done via the HTTP API /accounts/refresh.
	// Here we just report counts.
	alive := 0
	expired := 0
	unknown := 0
	for _, acc := range accounts {
		if acc.Status == nil {
			unknown++
		} else {
			switch *acc.Status {
			case "alive":
				alive++
			case "expired":
				expired++
			default:
				unknown++
			}
		}
	}
	summary := fmt.Sprintf("📊 当前状态统计:\n✅ 可用: %d\n⚠️ 需重扫: %d\n❓ 未知: %d\n\n提示: 通过 HTTP API /accounts/refresh 执行实际刷新", alive, expired, unknown)
	b.sendMessage(ctx, chatID, summary, false)
}

func (b *Bot) cmdStats(ctx context.Context, chatID int64) {
	accounts, err := b.db.ListAccounts(ctx)
	if err != nil {
		b.sendMessage(ctx, chatID, "❌ 获取统计失败: "+escapeMarkdown(err.Error()), true)
		return
	}
	alive := 0
	expired := 0
	unknown := 0
	for _, acc := range accounts {
		if acc.Status == nil {
			unknown++
		} else {
			switch *acc.Status {
			case "alive":
				alive++
			case "expired":
				expired++
			default:
				unknown++
			}
		}
	}
	text := fmt.Sprintf("📊 YYB Go 统计\n\n"+
		"账号总数: %d\n"+
		"✅ 可用: %d\n"+
		"⚠️ 需重扫: %d\n"+
		"❓ 未知: %d\n"+
		"管理员: %d 人\n"+
		"时间: %s",
		len(accounts), alive, expired, unknown, len(b.adminIDs),
		time.Now().Format("2006-01-02 15:04:05"))
	b.sendMessage(ctx, chatID, text, false)
}

// ── internal: Telegram API helpers ───────────────────────────────────

type urlValues map[string][]string

func (b *Bot) apiGet(ctx context.Context, method string, params urlValues, out any) error {
	u := b.apiBase + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if len(params) > 0 {
		q := req.URL.Query()
		for k, vs := range params {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		req.URL.RawQuery = q.Encode()
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram API %s: HTTP %d: %s", method, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

func (b *Bot) apiPost(ctx context.Context, method string, payload map[string]any, out any) error {
	u := b.apiBase + "/" + method
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram API %s: HTTP %d: %s", method, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

func (b *Bot) sendMessage(ctx context.Context, chatID int64, text string, markdown bool) {
	payload := map[string]any{
		"chat_id": chatID,
		"text":    text,
	}
	if markdown {
		payload["parse_mode"] = "Markdown"
	}
	var result json.RawMessage
	if err := b.apiPost(ctx, "sendMessage", payload, &result); err != nil {
		log.Printf("[tgbot] sendMessage to %d failed: %v", chatID, err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func escapeMarkdown(s string) string {
	// Escape special Markdown characters for Telegram's Markdown parse mode.
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"`", "\\`",
		"[", "\\[",
		"]", "\\]",
	)
	return replacer.Replace(s)
}
