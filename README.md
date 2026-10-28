# az-devops-token

Prints a short-lived Microsoft Entra access token for the internal Azure DevOps
Artifacts feeds, scoped to `vso.packaging` (Packaging read). Usable as an npm
`_authToken` or a NuGet feed password.

## Why not `az account get-access-token`

`az account get-access-token` returns a full `user_impersonation` token — it can
do anything the signed-in user can across all of Azure DevOps. This tool signs in
through a dedicated Entra **public-client** app that requests only the delegated
`vso.packaging` scope, so a leaked token can read feeds and nothing else. Tokens
are short-lived (~1h); the durable refresh token stays in a `0600` cache.

## Usage

Sign in once per machine (interactive browser sign-in):

```sh
az-devops-token login
```

Then print a token — silent, refreshing as needed:

```sh
az-devops-token print
```

The printed token has a guaranteed minimum remaining lifetime (currently
~20 minutes): if the cached token is closer to expiry, the tool forces a
refresh first. A caller can therefore cache it for any shorter interval (e.g.
mise's `env_cache_ttl`) without risking an expired credential.

Only `print` writes a token. `--help` (or `-h`, `help`) prints usage, and any
other invocation, including one with no arguments, prints usage to stderr and
exits `2`, so probing the CLI never writes a credential to stdout.

The `print` invocation always exits `0`. With no valid login it prints nothing
to stdout and a hint to stderr, so callers (e.g. mise `[env]`) degrade to a
clean `401` rather than erroring.

To check that sign-in works without printing a token:

```sh
az-devops-token status
```

`status` acquires a token the same way `print` does, then reports the account,
the token's expiry and the cache path instead of the token. It exits `0` when
a token is available and `1` otherwise, saying whether no one is signed in or
the acquisition itself failed (a network error, or an expired sign-in that
needs another `login`).

## Configuration

The Entra public-client app registration is identified by:

- `AZURE_CLIENT_ID` — application (client) ID
- `AZURE_TENANT_ID` — directory (tenant) ID

Released binaries have these baked in at build time (`-ldflags -X`); the
environment variables override for local builds and testing. Neither value is a
secret: a public client has no client secret, and issuing a token still requires
an interactive sign-in against the tenant.

The app registration must have:

- A **`http://localhost`** redirect URI under the **Mobile and desktop
  applications** platform (for the interactive browser sign-in; MSAL redirects to
  a loopback port)
- Delegated **Azure DevOps → `vso.packaging`** permission (self-consentable — no
  admin consent required)

It does *not* need **Allow public client flows** enabled — that setting only
gates device-code / ROPC / integrated-Windows auth, none of which this tool uses.

## Cache

The MSAL token cache (refresh token plus any live access token) is written to the
first of `$AZ_DEVOPS_TOKEN_CACHE`, `$XDG_CACHE_HOME/az-devops-token.json`, or
`~/.cache/az-devops-token.json`, with `0600` permissions.
