package token_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/energyworldnet/az-devops-token/internal/token"
)

func TestStripAccessTokensRemovesOnlyAccessTokens(t *testing.T) {
	in := []byte(`{` +
		`"AccessToken":{"k":{"secret":"at"}},` +
		`"RefreshToken":{"r":{"secret":"rt"}},` +
		`"IdToken":{"i":{}},` +
		`"Account":{"a":{}},` +
		`"AppMetadata":{"m":{}}` +
		`}`)

	out, err := token.StripAccessTokens(in)
	if err != nil {
		t.Fatalf("StripAccessTokens: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if _, ok := got["AccessToken"]; ok {
		t.Error("AccessToken section should be removed")
	}
	for _, key := range []string{"RefreshToken", "IdToken", "Account", "AppMetadata"} {
		if _, ok := got[key]; !ok {
			t.Errorf("%s section should be preserved", key)
		}
	}
}

func TestStripAccessTokensRejectsInvalidJSON(t *testing.T) {
	if _, err := token.StripAccessTokens([]byte("not json")); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func TestWithLockRunsFnAndReleases(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "cache.lock")

	ran := false
	locked, err := token.WithLock(context.Background(), lockPath, func() { ran = true })
	if err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if !locked {
		t.Fatal("expected to acquire an uncontended lock")
	}
	if !ran {
		t.Error("fn should have run while the lock was held")
	}

	// The lock must be released on return: a second acquisition succeeds.
	locked, err = token.WithLock(context.Background(), lockPath, func() {})
	if err != nil {
		t.Fatalf("WithLock (second): %v", err)
	}
	if !locked {
		t.Error("lock should be released after WithLock returns")
	}
}

func TestWithLockCreatesParentDir(t *testing.T) {
	// A not-yet-created cache dir (the pre-login state) must not stop the lock.
	lockPath := filepath.Join(t.TempDir(), "nested", "cache.lock")
	locked, err := token.WithLock(context.Background(), lockPath, func() {})
	if err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if !locked {
		t.Error("expected to acquire the lock after creating the parent dir")
	}
}

func TestWithLockContendedGivesUp(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "cache.lock")

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := token.WithLock(context.Background(), lockPath, func() {
			close(held)
			<-release
		})
		if err != nil {
			t.Errorf("holder WithLock: %v", err)
		}
	}()
	<-held // the lock is now held by the goroutine

	// A second acquisition under an expired context must give up without running
	// fn, so a latency-sensitive caller can degrade rather than block.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ran := false
	locked, err := token.WithLock(ctx, lockPath, func() { ran = true })
	if err != nil {
		t.Fatalf("contended WithLock: %v", err)
	}
	if locked {
		t.Error("should not acquire a lock another process holds")
	}
	if ran {
		t.Error("fn must not run when the lock is not acquired")
	}

	close(release)
	<-done
}

func TestNeedsForcedRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"ample life", now.Add(token.MinLifetime + time.Minute), false},
		{"exactly at bound", now.Add(token.MinLifetime), false},
		{"inside window", now.Add(token.MinLifetime - time.Minute), true},
		{"already expired", now.Add(-time.Minute), true},
	}
	for _, c := range cases {
		if got := token.NeedsForcedRefresh(c.expires, now); got != c.want {
			t.Errorf("%s: NeedsForcedRefresh = %v, want %v", c.name, got, c.want)
		}
	}
}
