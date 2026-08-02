package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"yyb_go/internal/store"
)

// ── HTTP handlers for WeChat Official Account binding & push ──

// POST /api/wx/bind-code  (requires yyb_user session cookie)
// Returns the current 6-digit bind code for the logged-in yyb account.
func (a *App) handleWxBindCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	acc, ok := a.getSessionAccount(w, r)
	if !ok {
		return
	}
	code, err := a.db.CreateBindCode(r.Context(), acc.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成绑定码失败")
		return
	}
	_, gzhOpenID, _ := a.db.GetBindCodeStatus(r.Context(), acc.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"bind_code": code,
		"bound":     gzhOpenID != nil,
		"gzh_link":  a.cfg.WxGzhLink,
		"gzh_name":  a.cfg.WxGzhName,
	})
}

// GET|POST /api/wx/bind-status  (requires yyb_user session cookie)
func (a *App) handleWxBindStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	acc, ok := a.getSessionAccount(w, r)
	if !ok {
		return
	}
	code, gzhOpenID, err := a.db.GetBindCodeStatus(r.Context(), acc.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"bound":    false,
			"gzh_link": a.cfg.WxGzhLink,
			"gzh_name": a.cfg.WxGzhName,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bound":      gzhOpenID != nil,
		"bind_code":  code,
		"gzh_link":   a.cfg.WxGzhLink,
		"gzh_name":   a.cfg.WxGzhName,
		"gzh_openid": gzhOpenID,
	})
}

// POST /api/wx/bind  (called by sillygirl plugin — no auth)
// Binds a wechat official account user (gid) to a bind_code.
// Body: { "bind_code": "123456", "gid": "wx_abc123" }
func (a *App) handleWxBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		BindCode string `json:"bind_code"`
		GID      string `json:"gid"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil || body.BindCode == "" || body.GID == "" {
		writeJSON(w, http.StatusOK, map[string]string{"message": "请输入完整指令，格式：yyb 绑定 您的绑定码"})
		return
	}
	body.BindCode = strings.TrimSpace(body.BindCode)
	body.GID = strings.TrimSpace(body.GID)

	accID, err := a.db.BindWxUser(r.Context(), body.BindCode, body.GID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("绑定失败：%s", err.Error())})
		return
	}
	// Push a welcome message after successful bind
	_, _ = a.db.PushWxMessage(r.Context(), accID, "bind_ok",
		"✅ 绑定成功！从现在起，您扫码登录yyb后可在公众号发送「yyb 取件」获取登录状态、京东验证结果等提醒。")
	writeJSON(w, http.StatusOK, map[string]string{"message": "✅ 绑定成功！后续登录状态、京东验证结果等消息可通过「yyb 取件」获取。"})
}

// GET /api/wx/pending?gid=wx_abc123  (called by sillygirl plugin — no auth)
// Returns up to N pending messages for the user; marks them read on return.
func (a *App) handleWxPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	gid := strings.TrimSpace(r.URL.Query().Get("gid"))
	if gid == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "error", "data": "缺少 gid 参数"})
		return
	}
	acc, err := a.db.GetAccountByGzhOpenID(r.Context(), gid)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "idle",
			"data":   "未找到绑定的YYB账号，请先在YYB网页端生成绑定码，然后在公众号发送「yyb 绑定 绑定码」",
		})
		return
	}
	msgs, err := a.db.FetchPendingMessages(r.Context(), acc.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "error", "data": "获取消息失败"})
		return
	}
	if len(msgs) == 0 {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "idle",
			"data":   "当前没有待取的消息。在YYB扫码登录或进行京东验证后会在这里显示。",
		})
		return
	}
	var b strings.Builder
	for i, m := range msgs {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(m.Content)
	}
	_ = a.db.MarkMessagesRead(r.Context(), acc.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "done", "data": b.String()})
}

// POST /api/wx/push  (protected — API token or admin session)
// Body: { "wechat_account_id": 1, "msg_type": "login", "content": "..." }
func (a *App) handleWxPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		WechatAccountID int64  `json:"wechat_account_id"`
		MsgType         string `json:"msg_type"`
		Content         string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.WechatAccountID == 0 || body.Content == "" {
		writeError(w, http.StatusBadRequest, "wechat_account_id and content required")
		return
	}
	if body.MsgType == "" {
		body.MsgType = "notification"
	}
	_, err := a.db.PushWxMessage(r.Context(), body.WechatAccountID, body.MsgType, body.Content)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── helper: get account from yyb_user session cookie ──

func (a *App) getSessionAccount(w http.ResponseWriter, r *http.Request) (*store.WechatAccount, bool) {
	token, _ := getCookie(r, "yyb_user")
	if token != "" {
		sess, err := a.db.GetUserSession(r.Context(), token)
		if err == nil && sess != nil {
			acc, err := a.db.GetAccount(r.Context(), sess.WechatAccountID)
			if err == nil && acc != nil {
				return acc, true
			}
		}
	}
	writeError(w, http.StatusUnauthorized, "请先扫码登录")
	return nil, false
}
