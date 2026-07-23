package token_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// lockHolderEnv names the env var that switches TestWithLockCrossProcess into
// its child (lock-holder) role. The child holds the lock on the named path
// until the parent closes its stdin.
const lockHolderEnv = "AZ_DEVOPS_TOKEN_TEST_LOCK_PATH"

// lockHeldSignal is written to stdout by the child once the lock is held, so
// the parent only starts contending after acquisition.
const lockHeldSignal = "LOCK_HELD"

func TestWithLockCrossProcess(t *testing.T) {
	if lockPath := os.Getenv(lockHolderEnv); lockPath != "" {
		// Child role: hold the lock until the parent closes our stdin (EOF),
		// signalling readiness first.
		_, _ = token.WithLock(context.Background(), lockPath, func() {
			fmt.Println(lockHeldSignal)
			_, _ = io.Copy(io.Discard, os.Stdin)
		})
		return
	}

	lockPath := filepath.Join(t.TempDir(), "cache.lock")

	// Re-exec this test binary as a separate process that holds the lock, to
	// exercise the genuinely cross-process advisory lock rather than same-process
	// scheduling.
	cmd := exec.Command(os.Args[0], "-test.run=^TestWithLockCrossProcess$") //nolint:gosec // re-execs this test binary itself, not external input
	cmd.Env = append(os.Environ(), lockHolderEnv+"="+lockPath)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	// Safety net: if an assertion below fails early, don't leave the child
	// blocked (and the lockfile undeletable).
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait until the child reports the lock is held, bounding the wait so a
	// stalled child (never signals) or one that exits before signalling (EOF)
	// fails fast with a clear diagnostic instead of hanging or falling through
	// to a misleading contended-lock assertion.
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == lockHeldSignal {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- fmt.Errorf("reading lock holder output: %w", err)
			return
		}
		ready <- fmt.Errorf("lock holder exited before signalling it held the lock")
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("waiting for lock holder: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for lock holder to acquire the lock")
	}

	// The lock is held by another process: acquisition must give up within the
	// deadline without running fn, so a latency-sensitive caller can degrade.
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

	// Release the holder and wait for it to exit, so the lock is fully released.
	if err := stdin.Close(); err != nil {
		t.Fatalf("close holder stdin: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("lock holder exited with error: %v", err)
	}

	// The lock is acquirable again now that the holder is gone.
	locked, err = token.WithLock(context.Background(), lockPath, func() {})
	if err != nil {
		t.Fatalf("post-release WithLock: %v", err)
	}
	if !locked {
		t.Error("lock should be acquirable after the holder exits")
	}
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
