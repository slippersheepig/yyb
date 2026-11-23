package protocol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	getA8KeyCmdID = 5112
)

var (
	getA8KeyURL = []byte("/ilink/ilinkapp/mm/ilinkgeta8key")

	a8KeyInputTagRE  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	a8KeyAttrNameRE  = regexp.MustCompile(`(?is)\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
	a8KeyAttrValueRE = regexp.MustCompile(`(?is)\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
	a8KeyVersionJSRE = regexp.MustCompile(`(?is)&version="\s*\+\s*encodeURIComponent\("([^"]+)"\)`)
	a8KeyAuthURLRE   = regexp.MustCompile(`(?is)var\s+authUrl\s*=\s*"([^"]+)"`)
)

// ErrH5A8KeyBusinessRejected reports a non-zero BaseResponse.Ret from
// /ilink/ilinkapp/mm/ilinkgeta8key (cmd 5112).
type ErrH5A8KeyBusinessRejected struct {
	Ret    int32
	ErrMsg string
}

func (e *ErrH5A8KeyBusinessRejected) Error() string {
	if e.ErrMsg != "" {
		return fmt.Sprintf("h5 a8key rejected: business code=%d (errmsg=%s)", e.Ret, e.ErrMsg)
	}
	return fmt.Sprintf("h5 a8key rejected: business code=%d", e.Ret)
}

// buildGetA8KeyRequest encodes WeChat's GetA8KeyRequest matching the verified
// ilinkgeta8key (cmd 5112) wire layout.
func buildGetA8KeyRequest(base []byte, targetURL string) []byte {
	out := pbLen(1, base)
	out = append(out, pbVar(2, 2)...)
	for _, n := range []int{4, 5, 6} {
		out = append(out, pbLen(n, pbLen(1, nil))...)
	}
	out = append(out, pbLen(7, pbLen(1, []byte(targetURL)))...)
	for _, v := range [][2]uint64{{9, 0}, {10, 1}, {14, 2}, {15, 100}} {
		out = append(out, pbVar(int(v[0]), v[1])...)
	}
	// Fields 16..19 require 2-byte protobuf tags (varint-encoded tag = field<<3|wire):
	//   16 (varint 0):       0x80 0x01 0x00
	//   17 (bytes "WIFI"):   0x8a 0x01 0x04 "WIFI"
	//   18 (varint 0):       0x90 0x01 0x00
	//   19 (varint 0):       0x98 0x01 0x00
	out = append(out, 0x80, 0x01, 0, 0x8a, 0x01, 4)
	out = append(out, []byte("WIFI")...)
	out = append(out, 0x90, 0x01, 0, 0x98, 0x01, 0)
	return out
}

// buildRoutePacket wraps an inner protobuf body for an independent iLink CGI
// (such as cmd 5112 /ilink/ilinkapp/mm/ilinkgeta8key), bypassing wxaruntime_transfer.
func buildRoutePacket(session AppSession, body []byte, cmd uint32, cgi []byte) ([]byte, error) {
	enc, err := aesGCMEncryptLayout(session.SendKey, nil, lz4AllLiteral(body))
	if err != nil {
		return nil, err
	}
	inner := buildShortlink(cmd, 0, append(sessionWpkgHead(session.UIN, session.F9, session.DeviceID), enc...), defaultVer)
	env := make([]byte, 0, 2+len(cgi)+2+len(transferHost)+4+len(inner))
	var tmp [4]byte
	binary.BigEndian.PutUint16(tmp[:2], uint16(len(cgi)))
	env = append(env, tmp[:2]...)
	env = append(env, cgi...)
	binary.BigEndian.PutUint16(tmp[:2], uint16(len(transferHost)))
	env = append(env, tmp[:2]...)
	env = append(env, transferHost...)
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(inner)))
	env = append(env, tmp[:4]...)
	env = append(env, inner...)
	out := make([]byte, 4, 4+len(env))
	binary.BigEndian.PutUint32(out[:4], uint32(len(env)))
	out = append(out, env...)
	return out, nil
}

// parseA8KeyResponse extracts BaseResponse.Ret (field 1.1) and FullURL (field 2)
// from GetA8KeyResp while tolerating repeated/non-length-delimited trailing fields.
func parseA8KeyResponse(raw []byte) (string, error) {
	var baseBytes, fullURLBytes []byte
	for offset := 0; offset < len(raw); {
		tag, next, err := readVarint(raw, offset)
		if err != nil || tag>>3 == 0 {
			break
		}
		offset = next
		fn := int(tag >> 3)
		wire := int(tag & 7)
		switch wire {
		case 0:
			_, offset, err = readVarint(raw, offset)
		case 1:
			if len(raw)-offset < 8 {
				err = errors.New("truncated fixed64")
			} else {
				offset += 8
			}
		case 2:
			var size uint64
			size, offset, err = readVarint(raw, offset)
			if err != nil || size > uint64(len(raw)-offset) {
				err = errors.New("truncated bytes field")
			} else {
				val := raw[offset : offset+int(size)]
				offset += int(size)
				if fn == 1 && baseBytes == nil {
					baseBytes = val
				} else if fn == 2 && fullURLBytes == nil {
					fullURLBytes = val
				}
			}
		case 5:
			if len(raw)-offset < 4 {
				err = errors.New("truncated fixed32")
			} else {
				offset += 4
			}
		default:
			err = errors.New("unsupported wire type")
		}
		if err != nil {
			break
		}
	}
	if len(baseBytes) == 0 {
		return "", errors.New("h5 a8key: missing explicit business status")
	}
	baseFields, err := parseH5OAuthFields(baseBytes)
	if err != nil {
		return "", fmt.Errorf("h5 a8key: invalid base response: %w", err)
	}
	retField, ok := baseFields[1]
	if !ok || retField.wire != 0 {
		return "", errors.New("h5 a8key: missing explicit business status")
	}
	ret := int32(retField.n)
	if ret != 0 {
		return "", &ErrH5A8KeyBusinessRejected{Ret: ret, ErrMsg: extractBaseErrMsg(baseFields)}
	}
	fullURL := strings.TrimSpace(string(fullURLBytes))
	if fullURL == "" {
		return "", errors.New("h5 a8key: response missing FullURL")
	}
	return fullURL, nil
}

func extractInputAttr(re *regexp.Regexp, tag string) string {
	m := re.FindStringSubmatch(tag)
	if len(m) < 4 {
		return ""
	}
	for _, v := range m[1:4] {
		if v != "" {
			return html.UnescapeString(v)
		}
	}
	return ""
}

// buildA8KeyAuthorizeReply parses the WeChat OAuth confirmation page (HTTP 200)
// and builds the https://open.weixin.qq.com/connect/oauth2/authorize_reply URL.
func buildA8KeyAuthorizeReply(page []byte, origin *url.URL, scope string) *url.URL {
	if scope != "snsapi_userinfo" && scope != "snsapi_base" {
		return nil
	}
	fields := map[string]string{}
	for _, tag := range a8KeyInputTagRE.FindAllString(string(page), -1) {
		name := strings.TrimSpace(extractInputAttr(a8KeyAttrNameRE, tag))
		if name != "" {
			fields[name] = extractInputAttr(a8KeyAttrValueRE, tag)
		}
	}
	if m := a8KeyAuthURLRE.FindSubmatch(page); len(m) == 2 {
		rawAuth := html.UnescapeString(string(m[1]))
		if u, err := url.Parse(rawAuth); err == nil {
			u = origin.ResolveReference(u)
			if u.Scheme == "https" && u.Host == "open.weixin.qq.com" && u.Path == "/connect/oauth2/authorize_reply" && u.User == nil && u.Query().Get("pass_ticket") != "" {
				return u
			}
		}
	}
	q := url.Values{"allow": {"1"}, scope: {"on"}}
	for _, k := range []string{"uuid", "uin", "key", "pass_ticket", "version"} {
		q.Set(k, fields[k])
	}
	if q.Get("version") == "" {
		if m := a8KeyVersionJSRE.FindSubmatch(page); len(m) == 2 {
			q.Set("version", html.UnescapeString(string(m[1])))
		}
	}
	for _, k := range []string{"uuid", "uin", "key", "pass_ticket"} {
		if q.Get(k) == "" {
			return nil
		}
	}
	return &url.URL{
		Scheme:   "https",
		Host:     "open.weixin.qq.com",
		Path:     "/connect/oauth2/authorize_reply",
		RawQuery: q.Encode(),
	}
}

// executeA8KeyWebAuthorize fetches the ticketed open.weixin.qq.com authorize URL
// returned by GetA8Key (and confirms via authorize_reply if WeChat serves a 200
// confirmation form). It strictly talks only to open.weixin.qq.com and never
// contacts the caller's business redirect_uri.
func executeA8KeyWebAuthorize(ctx context.Context, ticketedURL, callback, scope, state string) (string, error) {
	u, err := url.Parse(ticketedURL)
	if err != nil || u.Scheme != "https" || u.Host != "open.weixin.qq.com" || u.Path != "/connect/oauth2/authorize" || u.User != nil {
		return "", errors.New("h5 a8key: unexpected authorization URL host/path")
	}
	if u.Query().Get("state") != state {
		return "", errors.New("h5 a8key: authorization URL state mismatch")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	referer := u.String()
	confirmed := false
	for step := 0; step < 3; step++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", fmt.Errorf("h5 a8key: build web request: %w", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.53(0x18003531) NetType/WIFI Language/zh_CN")
		if step > 0 {
			req.Header.Set("Referer", referer)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("h5 a8key: web request step %d failed: %w", step+1, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		_ = resp.Body.Close()
		if readErr != nil || len(body) > 1<<20 {
			return "", fmt.Errorf("h5 a8key: web response step %d unreadable", step+1)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			if loc == "" {
				return "", fmt.Errorf("h5 a8key: empty redirect location at step %d", step+1)
			}
			// Follow internal open.weixin.qq.com redirect before confirmation, else validate business callback.
			if step < 2 {
				if nextU, parseErr := url.Parse(loc); parseErr == nil {
					nextU = u.ResolveReference(nextU)
					if nextU.Scheme == "https" && nextU.Host == "open.weixin.qq.com" && (nextU.Path == "/connect/oauth2/authorize" || nextU.Path == "/connect/oauth2/authorize_reply") {
						referer = u.String()
						u = nextU
						continue
					}
				}
			}
			return h5OAuthCallbackCode(loc, callback, state)
		}
		if !confirmed && step < 2 && resp.StatusCode == http.StatusOK {
			next := buildA8KeyAuthorizeReply(body, u, scope)
			if next != nil {
				confirmed = true
				referer = u.String()
				u = next
				continue
			}
			return "", errors.New("h5 a8key: authorization confirmation form missing required fields")
		}
		return "", fmt.Errorf("h5 a8key: unexpected HTTP %d at step %d", resp.StatusCode, step+1)
	}
	return "", errors.New("h5 a8key: authorization did not complete")
}

// getH5CodeViaA8Key fetches an H5 OAuth code via independent iLink GetA8Key
// (cmd 5112, /ilink/ilinkapp/mm/ilinkgeta8key) + open.weixin.qq.com web confirmation.
func (p *Pool) getH5CodeViaA8Key(ctx context.Context, st WmpfSession, appID, authURL, callback, scope, state string) (map[string]any, error) {
	sessDev := stableSessDevice(st.Session.UIN)
	base := sessionInfo(uint32(st.Session.UIN), windowsName, sessDev)
	reqBody := buildGetA8KeyRequest(base, authURL)
	envelope, err := buildRoutePacket(st.Session, reqBody, getA8KeyCmdID, getA8KeyURL)
	if err != nil {
		return nil, err
	}
	_, reply, err := p.sendEnvelope(ctx, st, envelope)
	if err != nil {
		return nil, err
	}
	ticketedURL, err := parseA8KeyResponse(reply)
	if err != nil {
		return nil, err
	}
	code, err := executeA8KeyWebAuthorize(ctx, ticketedURL, callback, scope, state)
	if err != nil {
		return nil, err
	}
	log.Printf("[pool] H5 OAuth succeeded via A8Key(5112) app=%s scope=%s", appID, scope)
	return map[string]any{
		"code":         code,
		"appid":        appID,
		"scope":        scope,
		"state":        state,
		"redirect_uri": callback,
		"mode":         "h5_a8key_5112",
	}, nil
}
