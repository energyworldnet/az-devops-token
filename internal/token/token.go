// Package token acquires short-lived Microsoft Entra access tokens for the
// internal Azure DevOps Artifacts feeds, scoped to vso.packaging, and persists
// MSAL's token cache to disk.
//
// Tokens returned by Silent are guaranteed to have at least MinLifetime
// remaining, so a consumer may cache one for any TTL below that bound (e.g.
// mise's env_cache_ttl) without ever serving it past its own expiry.
package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/gofrs/flock"
)

// adoResource is the public, global Azure DevOps resource ID (identical for
// every tenant — not a secret). The requested scope narrows the token to feed
// reads.
const adoResource = "499b84ac-1321-427f-aa17-267ca6975798"

// MinLifetime is the smallest remaining lifetime a token from Silent may have.
// When the cached token has less, Silent forces a refresh, so the returned
// token is always good for at least this long. That lets a consumer cache it
// for any TTL strictly below this bound and never serve an expired token. Entra
// feed tokens live ~1h, so this leaves ample refresh headroom.
const MinLifetime = 20 * time.Minute

// lockRetryDelay is how long WithLock sleeps between attempts to acquire a
// contended cross-process lock. Operations under the lock are sub-second, so a
// short poll keeps a waiter's latency low without busy-spinning.
const lockRetryDelay = 50 * time.Millisecond

// Scopes returns the delegated scopes requested for a feed token.
func Scopes() []string { return []string{adoResource + "/vso.packaging"} }

// FileCache persists MSAL's token cache (which holds the refresh token and any
// live access token) to disk so a single login survives across invocations.
type FileCache struct {
	// Path is the on-disk location of the serialized MSAL cache.
	Path string
	// DropAccessTokens hides the cached access tokens on the next Replace so a
	// silent acquisition redeems the refresh token instead of returning a
	// near-expiry cached token. See Silent.
	DropAccessTokens bool
}

func (c *FileCache) Replace(_ context.Context, u cache.Unmarshaler, _ cache.ReplaceHints) error {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A missing cache is the normal pre-login state, not an error.
			return nil
		}
		return fmt.Errorf("read MSAL cache: %w", err)
	}
	if c.DropAccessTokens {
		data, err = StripAccessTokens(data)
		if err != nil {
			return err
		}
	}
	return u.Unmarshal(data)
}

// Export writes atomically (temp + rename, 0600) so concurrent shim invocations
// never read a half-written cache.
func (c *FileCache) Export(_ context.Context, m cache.Marshaler, _ cache.ExportHints) error {
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", c.Path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

// WithLock runs fn while holding an exclusive cross-process advisory lock on
// lockPath, then releases it. It serializes the whole reload → refresh →
// export sequence across concurrent invocations so a later writer's Export
// cannot clobber a newer refresh-token/cache update a peer just wrote. The
// lock is an OS advisory lock, so it is released automatically if the process
// dies mid-operation — a crash leaves no stale lock.
//
// It blocks (polling every lockRetryDelay) until the lock is acquired or ctx is
// done. When ctx expires first it returns (false, nil) without running fn, so a
// caller on a latency-sensitive path can degrade rather than hang. A genuine
// lock error (e.g. the lock directory cannot be created) is returned as-is.
func WithLock(ctx context.Context, lockPath string, fn func()) (bool, error) {
	/* The lock is acquired before Export creates the cache directory, so
	   ensure the parent exists first (mirrors Export). Otherwise the first run
	   on a machine with a not-yet-created cache dir couldn't create the
	   lockfile. */
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return false, err
	}
	fl := flock.New(lockPath)
	locked, err := fl.TryLockContext(ctx, lockRetryDelay)
	if err != nil {
		/* A context error means we simply ran out of time waiting for a peer to
		   release — report it as a clean give-up (false, nil) so the caller can
		   degrade, not as a failure. */
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return false, nil
		}
		return false, err
	}
	if !locked {
		return false, nil
	}
	defer fl.Unlock() //nolint:errcheck // advisory lock; unlock errors aren't actionable and the OS releases it on exit
	fn()
	return true, nil
}

// StripAccessTokens removes the access-token entries from a serialized MSAL
// cache, leaving the refresh token and everything else intact. MSAL's silent
// path then finds no cached access token and redeems the refresh token for a
// freshly-minted one (apps/internal/base: "redeem a cached refresh token").
func StripAccessTokens(data []byte) ([]byte, error) {
	var contents map[string]json.RawMessage
	if err := json.Unmarshal(data, &contents); err != nil {
		return nil, err
	}
	delete(contents, "AccessToken")
	return json.Marshal(contents)
}

// NeedsForcedRefresh reports whether a token expiring at expiresOn has too
// little life left to return under the MinLifetime guarantee.
func NeedsForcedRefresh(expiresOn, now time.Time) bool {
	return expiresOn.Sub(now) < MinLifetime
}

// Silent returns a cached or silently-refreshed access token, if the account
// has a prior login that is still valid or refreshable. The returned token is
// guaranteed to have at least MinLifetime remaining: MSAL refreshes proactively
// only when Entra sends refresh_in, so when it doesn't, the cached token is
// returned until it actually expires. If the token is inside that window, Silent
// forces a refresh-token grant by hiding the cached access token (see FileCache).
func Silent(ctx context.Context, app public.Client, fc *FileCache) (string, bool) {
	accounts, err := app.Accounts(ctx)
	if err != nil || len(accounts) == 0 {
		return "", false
	}
	acct := accounts[0]

	res, err := app.AcquireTokenSilent(ctx, Scopes(), public.WithSilentAccount(acct))
	if err != nil {
		return "", false
	}
	if !NeedsForcedRefresh(res.ExpiresOn, time.Now()) {
		return res.AccessToken, true
	}

	fc.DropAccessTokens = true
	defer func() { fc.DropAccessTokens = false }()
	res, err = app.AcquireTokenSilent(ctx, Scopes(), public.WithSilentAccount(acct))
	if err != nil {
		return "", false
	}
	return res.AccessToken, true
}
