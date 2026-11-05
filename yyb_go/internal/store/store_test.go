package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAndAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yyb.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	acc, err := db.UpsertAccount(ctx, "test-openid", "test-buffer", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	if acc == nil || acc.OpenID != "test-openid" {
		t.Fatalf("unexpected account: %#v", acc)
	}

	fetched, err := db.GetAccount(ctx, acc.ID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if fetched == nil || fetched.OpenID != "test-openid" {
		t.Fatalf("unexpected fetched account: %#v", fetched)
	}
}
