package token_test

import (
	"encoding/json"
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
