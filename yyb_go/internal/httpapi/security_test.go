package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrepareDBPathRejectsPathTraversal(t *testing.T) {
	if _, err := prepareDBPath(t.TempDir(), "../yyb.db"); err == nil {
		t.Fatal("prepareDBPath accepted filename with path separator")
	}
}

func TestSessionCookieSecureBehindHTTPSProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	cookie := sessionCookie(req, "yyb_admin", "token", time.Now().Add(time.Hour))
	if !cookie.Secure {
		t.Fatal("sessionCookie did not set Secure for HTTPS proxy requests")
	}
	if !cookie.HttpOnly {
		t.Fatal("sessionCookie did not set HttpOnly")
	}
}

func TestValidatedAutopostURLRequiresHTTPSOutsideLoopback(t *testing.T) {
	if _, err := validatedAutopostURL("http://autopost.example.test"); err == nil {
		t.Fatal("validatedAutopostURL accepted non-loopback HTTP URL")
	}
	if _, err := validatedAutopostURL("https://autopost.example.test/base"); err != nil {
		t.Fatalf("validatedAutopostURL rejected HTTPS URL: %v", err)
	}
	if _, err := validatedAutopostURL("http://127.0.0.1:9000"); err != nil {
		t.Fatalf("validatedAutopostURL rejected loopback HTTP URL: %v", err)
	}
}

func TestLoginCookieSetsSecureBehindHTTPSProxy(t *testing.T) {
	t.Setenv("GIN_MODE", "test")

	app, err := NewApp(Config{
		ResourceRoot: t.TempDir(),
		WebUser:      "admin",
		WebPass:      "secret",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	body := strings.NewReader("username=admin&password=secret")
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	setCookie := rec.Header().Values("Set-Cookie")
	if len(setCookie) == 0 || !strings.Contains(setCookie[0], "Secure") {
		t.Fatalf("login cookie missing Secure attribute: %#v", setCookie)
	}
}
