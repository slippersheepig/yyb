package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"yyb_go/internal/httpapi"
	"yyb_go/internal/tgbot"
)

func parseAllowedIPs(s string) []string {
    if s == "" {
        return nil
    }
    var ips []string
    for _, ip := range strings.Split(s, ",") {
        ip = strings.TrimSpace(ip)
        if ip != "" {
            ips = append(ips, ip)
        }
    }
    return ips
}

// parseAdminIDs parses a comma-separated list of Telegram user IDs.
// Example: "123456789,987654321"
func parseAdminIDs(s string) []int64 {
    if s == "" {
        return nil
    }
    var ids []int64
    for _, part := range strings.Split(s, ",") {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        id, err := strconv.ParseInt(part, 10, 64)
        if err != nil {
            log.Printf("[main] invalid TG_ADMIN_IDS entry %q: %v", part, err)
            continue
        }
        ids = append(ids, id)
    }
    return ids
}

func main() {
	host := flag.String("host", "127.0.0.1", "listen host")
	port := flag.Int("port", 8000, "listen port")
	resourceRoot := flag.String("resource-root", filepath.Join(".", "resource"), "runtime resource directory")
	dbFilename := flag.String("db", httpapi.DefaultDBFilename, "SQLite database filename under resource/db")
	tcpProxy := flag.String("tcp-proxy", "", "optional TCP proxy: socks5://host:port or http-connect://host:port")
	flag.Parse()

	cfg := httpapi.Config{
		ResourceRoot:   *resourceRoot,
		DBFilename:     *dbFilename,
		TCPProxy:       *tcpProxy,
		SessionTTL:     30 * time.Minute,
		RequestTimeout: 8 * time.Second,
		AvatarTimeout:  10 * time.Second,
		ScanTimeout:    180 * time.Second,
		QRSessionTTL:   5 * time.Minute,
		APIToken:       os.Getenv("YYB_API_TOKEN"),
		AllowedIPs:     parseAllowedIPs(os.Getenv("YYB_ALLOWED_IPS")),
		TGBotToken:     os.Getenv("TG_BOT_TOKEN"),
		TGAdminIDs:     parseAdminIDs(os.Getenv("TG_ADMIN_IDS")),
	}

	app, err := httpapi.NewApp(cfg)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}
	defer app.Close()

	// Start Telegram bot if configured.
	var bot *tgbot.Bot
	if cfg.TGBotToken != "" && len(cfg.TGAdminIDs) > 0 {
		bot = tgbot.New(tgbot.Config{
			Token:    cfg.TGBotToken,
			AdminIDs: cfg.TGAdminIDs,
		}, app.DB())
		if bot != nil {
			app.SetTelegramBot(bot)
			bot.Start(context.Background())
			defer bot.Stop()
			log.Printf("[main] Telegram bot started with %d admin(s)", len(cfg.TGAdminIDs))
		}
	} else {
		log.Println("[main] Telegram bot not configured (TG_BOT_TOKEN / TG_ADMIN_IDS not set)")
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("YYB Go service listening on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
