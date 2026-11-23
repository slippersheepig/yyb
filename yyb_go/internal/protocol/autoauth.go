package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"
)

const cmdAutoAuth = 3198

// AutoAuthState stores independent iLink AutoAuth key material (AuthSectResp
// fields 3 & 4) bound to the AppBase device used during ManualAuth.
// AttemptedAt is persisted BEFORE sending a rotating AutoKey so an ambiguous
// disconnect or restart never replays a consumed key.
type AutoAuthState struct {
	Device      []byte
	Key         []byte
	EncKey      []byte
	AttemptedAt int64
}

func (s AutoAuthState) Usable() bool {
	return len(s.Device) > 0 && len(s.Key) > 0 && len(s.EncKey) == 24 && s.AttemptedAt == 0
}

type AutoAuthRejectedError struct {
	Stage string
	Code  int64
}

func (e *AutoAuthRejectedError) Error() string {
	return fmt.Sprintf("native autoauth %s rejected: code=%d", e.Stage, e.Code)
}

func autoAuthFromUnified(unified, device []byte) AutoAuthState {
	sect := pbParse(safeBytes(pbParse(unified)[2]))
	return AutoAuthState{
		Device: append([]byte(nil), device...),
		Key:    safeBytes(sect[3]),
		EncKey: safeBytes(sect[4]),
	}
}

func autoAuthFromManualAuth(mar, device []byte) AutoAuthState {
	unified := safeBytes(pbParse(mar)[3])
	if len(unified) == 0 {
		return AutoAuthState{}
	}
	return autoAuthFromUnified(unified, device)
}

func buildAutoAuth(saved WmpfSession, temp *manualAuthTemp) ([]byte, error) {
	if !saved.AutoAuth.Usable() || saved.Session.UIN == 0 || len(saved.Session.F9) == 0 || len(saved.Session.DeviceID) == 0 {
		return nil, errors.New("native autoauth state incomplete or already attempted")
	}
	request := append(pbLen(1, pbLen(1, saved.AutoAuth.Device)), pbVar(2, appVersion)...)
	request = append(request, pbLen(3, saved.AutoAuth.Key)...)
	hybrid, err := hybridECDHEncryptWithKey(request, serverPub, saved.AutoAuth.EncKey, temp)
	if err != nil {
		return nil, err
	}
	ints, byts, _, err := decodeWpkgHead(sessionWpkgHead(saved.Session.UIN, saved.Session.F9, saved.Session.DeviceID))
	if err != nil {
		return nil, err
	}
	ints[25] = 17
	return append(wpkgHead(ints, byts), hybrid...), nil
}

const applicationSigningPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElsQBff9Ng3kBHy/H+EH4c86qn/iS
0zRmO0XcMQJdxeATvpBKd0BtdhSdPAvYkB/b/ho5Z4o5wwEJW94vlAFCag==
-----END PUBLIC KEY-----`

func verifyHybridSignature(requestCipher, response []byte) error {
	block, _ := pem.Decode([]byte(applicationSigningPublicKey))
	if block == nil {
		return errors.New("failed to decode native signing public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid native signing public key")
	}
	fields := pbParse(response)
	cipherBytes, sig := safeBytes(fields[3]), safeBytes(fields[4])
	if len(requestCipher) == 0 || len(cipherBytes) == 0 || len(sig) == 0 {
		return errors.New("native signature inputs incomplete")
	}
	h := sha256.New()
	_, _ = h.Write(requestCipher)
	_, _ = h.Write(cipherBytes)
	digest := sha256.Sum256(h.Sum(nil))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("native response signature mismatch")
	}
	return nil
}

func parseAutoAuthResponse(packet shortlinkPacket, saved WmpfSession, temp *manualAuthTemp) (WmpfSession, error) {
	if temp == nil || temp.Ephemeral == nil || len(temp.OKM) != 56 {
		return WmpfSession{}, errors.New("native autoauth request state incomplete")
	}
	if packet.Cmd != cmdAutoAuth {
		return WmpfSession{}, fmt.Errorf("unexpected native autoauth response command: %d", packet.Cmd)
	}
	ints, _, hlen, err := decodeWpkgHead(packet.Body)
	if err != nil || hlen >= len(packet.Body) {
		if err == nil && ints[4] != 0 {
			return WmpfSession{}, &AutoAuthRejectedError{Stage: "transport", Code: int64(int32(ints[4]))}
		}
		if err == nil && ints[23] != 0 {
			return WmpfSession{}, &AutoAuthRejectedError{Stage: "application", Code: int64(int32(ints[23]))}
		}
		return WmpfSession{}, errors.New("native autoauth response missing body")
	}
	if ints[4] != 0 {
		return WmpfSession{}, &AutoAuthRejectedError{Stage: "transport", Code: int64(int32(ints[4]))}
	}
	if ints[23] != 0 {
		return WmpfSession{}, &AutoAuthRejectedError{Stage: "application", Code: int64(int32(ints[23]))}
	}
	response := packet.Body[hlen:]
	credType, _ := pbParse(response)[2].(int64)
	if credType != 1 && credType != 2 {
		return WmpfSession{}, fmt.Errorf("unsupported native credential type: %d", credType)
	}
	if credType == 1 {
		if err = verifyHybridSignature(temp.RequestCipher, response); err != nil {
			return WmpfSession{}, err
		}
	}
	decoded, err := hybridECDHDecrypt(response, temp)
	if err != nil {
		return WmpfSession{}, errors.New("native autoauth response authentication failed")
	}
	fields := pbParse(decoded)
	base, unified := safeBytes(fields[1]), safeBytes(fields[2])
	if len(base) == 0 {
		return WmpfSession{}, errors.New("native autoauth response missing result")
	}
	if code, _ := pbParse(base)[1].(int64); code != 0 {
		return WmpfSession{}, &AutoAuthRejectedError{Stage: "business", Code: int64(int32(code))}
	}
	session, err := extractSession(append(pbLen(1, base), pbLen(3, unified)...))
	if err != nil {
		return WmpfSession{}, errors.New("native autoauth session incomplete")
	}
	nextAuth := autoAuthFromUnified(unified, saved.AutoAuth.Device)
	if session.UIN != saved.Session.UIN || !nextAuth.Usable() || len(session.F9) == 0 {
		return WmpfSession{}, errors.New("native autoauth identity or rotated keys incomplete")
	}
	session.DeviceID = saved.Session.DeviceID
	session.HostAppID = saved.Session.HostAppID
	saved.Session = session
	saved.AutoAuth = nextAuth
	saved.CreatedAt = time.Now()
	return saved, nil
}

// autoAuthSession connects once and sends cmdAutoAuth (3198) exactly once.
// consume() MUST persist AttemptedAt before transmission so a lost response
// never causes a rotating AutoKey to be replayed on another LongLink node.
func (p *Pool) autoAuthSession(ctx context.Context, saved WmpfSession, consume func() error) (WmpfSession, error) {
	temp := &manualAuthTemp{}
	body, err := buildAutoAuth(saved, temp)
	if err != nil {
		return WmpfSession{}, err
	}
	targets, err := getLonglinkTargets(ctx, p.cfg.LoginTimeout, p.cfg.DNSCacheTTL)
	if err != nil || len(targets) == 0 {
		return WmpfSession{}, errors.New("native autoauth LongLink target unavailable")
	}
	targets = orderLonglinkTargets(targets, 6)
	mc, err := connectMmtls(ctx, targets[0], p.cfg.LoginTimeout, saved.TCPProxy, p.cfg.TCPProxyFallbackDirect)
	if err != nil {
		return WmpfSession{}, err
	}
	defer mc.close()
	if err = consume(); err != nil {
		return WmpfSession{}, err
	}
	if err = mc.sendApp(cmdAutoAuth, body); err != nil {
		return WmpfSession{}, err
	}
	packet, err := mc.recvApp()
	if err != nil {
		return WmpfSession{}, err
	}
	next, err := parseAutoAuthResponse(packet, saved, temp)
	if err != nil {
		return WmpfSession{}, err
	}
	psks, err := mc.extractPSKs()
	if err != nil {
		next.PSK = pskEntry{ExpiredAt: time.Now().Add(-time.Second).Unix()}
		return next, err
	}
	psk, ok := pickAccessPSK(psks)
	if !ok {
		next.PSK = pskEntry{ExpiredAt: time.Now().Add(-time.Second).Unix()}
		return next, errors.New("native autoauth returned no access PSK")
	}
	next.PSK = psk
	next.ShortlinkTargets = getShortlinkTargets(ctx, p.cfg.ShortlinkTimeout, p.cfg.DNSCacheTTL)
	return next, nil
}

// TryNativeAutoAuth attempts an independent iLink AutoAuth (cmd 3198) rotation
// using persisted AutoKey/EncKey material from the cached session, without
// needing a valid OAuth token or login_buffer.
func (p *Pool) TryNativeAutoAuth(ctx context.Context, accountID int64, tcpProxy string) error {
	effective := effectiveProxy(tcpProxy, p.cfg.TCPProxy)
	lock := p.lockFor(fmt.Sprintf("%d\x00%s", accountID, effective))
	lock.Lock()
	defer lock.Unlock()

	row, err := p.db.GetSessionAny(ctx, accountID, effective)
	if err != nil {
		return err
	}
	saved, err := sessionFromBlob(row.SessionBlob)
	if err != nil {
		return err
	}
	if !saved.AutoAuth.Usable() {
		return errors.New("native autoauth unavailable or already attempted")
	}
	if err = acquire(ctx, p.loginSem); err != nil {
		return err
	}
	defer release(p.loginSem)

	authCtx, cancel := context.WithTimeout(ctx, p.cfg.LoginTimeout)
	defer cancel()

	next, exchangeErr := p.autoAuthSession(authCtx, saved, func() error {
		marked := saved
		marked.AutoAuth.AttemptedAt = time.Now().Unix()
		uin := marked.Session.UIN
		return p.db.PutSession(context.WithoutCancel(ctx), accountID, &uin, marked.toBlob(), sessionExpiresAt(marked, p.cfg.SessionTTL), effective)
	})
	if exchangeErr != nil && !next.AutoAuth.Usable() {
		log.Printf("[pool] account %d native AutoAuth failed: %v", accountID, exchangeErr)
		return exchangeErr
	}
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer saveCancel()
	uin := next.Session.UIN
	expiresAt := sessionExpiresAt(next, p.cfg.SessionTTL)
	if saveErr := p.db.PutSession(saveCtx, accountID, &uin, next.toBlob(), expiresAt, effective); saveErr != nil {
		return saveErr
	}
	log.Printf("[pool] account %d native AutoAuth succeeded (uin=%d, psk_lifetime=%ds)", accountID, uin, next.PSK.Lifetime)
	return exchangeErr
}
