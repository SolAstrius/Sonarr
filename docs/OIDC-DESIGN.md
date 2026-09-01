# OIDC / Authentik sign-in for Sonarr (and Radarr)

Design notes for adding OpenID Connect to the fork. Written against
`sol/4.0.19.2979` (Sonarr 4.0.19, net6.0). Radarr 6.3.0.10514 (net8.0) has a
file-for-file equivalent auth tree, so everything here ports with a namespace
swap; the only difference found is that Radarr has no `BasicAuthenticationHandler`.

## What exists today

Two **disjoint** gates over disjoint URL sets. Neither substitutes for the other.

| Gate | Covers | Enforced by |
|---|---|---|
| API key | everything under `/api/v3` + SignalR | `Startup.cs` `FallbackPolicy`, built on the single scheme `"API"` |
| User login | `StaticResourceController`, `InitializeJsonController` — the JS bundle and `initialize.json`. Nothing else. | `[Authorize(Policy = "UI")]` |

No API controller carries an `[Authorize]` attribute, so a Forms cookie is never
consulted on an API route. Conversely the API key is a single static string
compared with `==`, granting every endpoint with no identity attached (the
handler emits one claim, literally `ApiKey = "true"`).

The two gates are bridged in one place — `InitializeJsonController` prints the
key into the page:

    builder.AppendLine($"  \"apiKey\": \"{_apiKey}\",");

So today's login is **a gate standing in front of a shared god key**, not an
identity system. Anyone who completes it reads the key and keeps it forever.
Any SSO work that stops before fixing this inherits that property.

`UiAuthorizationPolicyProvider` rebuilds the `"UI"` policy per request from
`config.AuthenticationMethod`, naming a scheme by `ToString()` of the enum. That
dynamic lookup is the extension point: add an enum value, register a scheme
under the same name, and the policy provider picks it up with no changes.

`External` is worth knowing: it maps to `NoAuthenticationHandler`, the exact
class `None` uses. It succeeds with an `Anonymous` principal and imports no
identity from the proxy.

## Options

### 0. Reverse-proxy forward-auth — no fork

Set `AuthenticationMethod=External`, put a traefik `forwardAuth` middleware to
the Authentik outpost on the IngressRoute (ns `backends` already holds an
`authentik-auth` middleware next to the `arr-allowlist` one in use today).

- **For:** zero code, zero rebase debt, applies uniformly to Radarr, Prowlarr,
  Lidarr, everything behind the same ingress.
- **Against:** protects only north-south traffic. East-west callers hitting the
  ClusterIP directly (Prowlarr → Sonarr, `arr-mcp`, `exportarr`) bypass it
  completely. And `/api` must be carved out for machine clients holding the API
  key — which is precisely the full-power hole left open.
- **Verdict:** best value per unit of effort for the web UI. Do this regardless;
  it is not mutually exclusive with the rest.

### 1. In-app OIDC for the UI — the actual fork feature

Add `AuthenticationType.Oidc = 4` and register it.

The catch: a remote handler (OpenIdConnect) cannot serve as a policy's
*authenticate* scheme — it challenges, and the resulting identity lives in a
cookie. But `UiAuthorizationPolicyProvider` names exactly one scheme, the
`ToString()` of the method. Resolve it with scheme forwarding:

- register a **cookie** scheme named `Oidc` (so the existing policy resolves it),
  with `ForwardChallenge = "OidcRemote"`;
- register `.AddOpenIdConnect("OidcRemote", …)` with `SignInScheme = "Oidc"`.

`UiAuthorizationPolicyProvider` then needs no edit at all.

Touch list:

| File | Change |
|---|---|
| `NzbDrone.Core/Authentication/AuthenticationType.cs` | add `Oidc = 4` |
| `Sonarr.Http/Authentication/AuthenticationBuilderExtensions.cs` | cookie scheme `Oidc` + `AddOpenIdConnect("OidcRemote")` |
| `NzbDrone.Common/Options/AuthOptions.cs` | `Authority`, `ClientId`, `ClientSecret`, `Scopes`, `RequiredGroup` |
| `NzbDrone.Core/Configuration/ConfigFileProvider.cs` | matching config.xml keys via the `GetValue`/`SetValue` pattern |
| `Sonarr.Http/Authentication/AuthenticationController.cs` | `/login` returns `Challenge()` when method is `Oidc`; `/logout` signs out cookie **and** OIDC end-session |
| `Sonarr.Http/Sonarr.Http.csproj` | `Microsoft.AspNetCore.Authentication.OpenIdConnect` |

Notes:

- That package is **not** in the ASP.NET shared framework (it moved out at 3.0).
  Pin `6.0.x` for Sonarr, `8.0.x` for Radarr.
- Config binds from section `Sonarr:Auth` with `AddEnvironmentVariables()` and no
  prefix, so every new field is settable as `Sonarr__Auth__Authority` etc. —
  which is how the k8s Deployment should carry it, secret in a `Secret`.
- Data protection keys are already persisted to `/config`
  (`Startup.cs`: `PersistKeysToFileSystem`), so cookies survive restarts and
  would survive multiple replicas sharing `/config`.
- Redirect URI is `https://sonarr.media.sol.moe/signin-oidc`; mind `UrlBase`
  (currently empty) if that ever changes.
- `login.html` is a static page, not React, so "Sign in with Authentik" is
  either a one-line static edit or skipped entirely by challenging from the route.
- Mapping an Authentik **group claim** to allow/deny is the thing forward-auth in
  front of a shared key cannot give you: real authorization, evaluated in-app.

### 2. Close the key leak — what makes option 1 mean anything

Without this, OIDC login still ends in "here is the god key".

- Add the cookie scheme to the API `FallbackPolicy` alongside `"API"`, so both a
  session and a key authenticate an API call.
- Drop `apiKey` from `initialize.json`.
- Remove the three places the frontend attaches it — same-origin cookies take over:
  - `frontend/src/Utilities/createAjaxRequest.js:16`
  - `frontend/src/Helpers/Hooks/useApiQuery.ts:35`
  - `frontend/src/Components/SignalRConnector.js:108` (`access_token` query param)
- Keep `CalendarLinkModalContent.tsx` on a key — an iCal URL fetched by a third
  party genuinely needs one; it should hand out a key, not a session.

Machine clients (Prowlarr, `arr-mcp`, `exportarr`) keep working untouched
because the policy accepts both schemes. Three call sites is the whole cost.

### 3. Per-user API tokens

Replace the single config key with a table, issue tokens after OIDC login, attach
identity to API calls. Real work — `ApiKeyAuthenticationHandler`, a repository, a
migration, UI. Only worth it if attribution per client matters. Deferred.

## Recommended order

1. Forward-auth now (option 0) — free, and it hardens the UI today.
2. Option 1 in the fork, Sonarr first, then port to Radarr verbatim.
3. Option 2 immediately after 1 — without it, 1 is decorative.

## Risks / gotchas

- **East-west is still open** under every option. Sonarr's ClusterIP answers any
  pod in the cluster with the API key and no proxy in the path. Keep
  `arr-allowlist`, and consider a NetworkPolicy in ns `media`.
- **Break-glass.** A misconfigured authority locks you out of the UI. `AuthOptions`
  is env-bound, so `Sonarr__Auth__Method=Forms` on the Deployment is the recovery
  path — verify it works *before* switching the stored config.
- **Rebase cost.** ~6 files, all small, but they sit in the auth path that
  upstream does touch. Expect a rebase per release you follow; the Radarr patch
  is the same patch, so the cost is paid roughly once.
- `Sonarr__Auth__Enabled=true` forces `Basic` *and rewrites config.xml* as a side
  effect of reading the property. Don't set it.

---

# As built

Options 1 and 2 are implemented on `sol/oidc` and build clean through
`docker-sonarr`'s `Dockerfile.source`. Image: `registry.sol.moe/sonarr:4.0.19.2979-oidc9`.

## Config surface

All read-only from config.xml or env (section `Sonarr:Auth`, no prefix), never
persisted back, so a bad value is always correctable from the Deployment alone:

| Env var | config.xml key | Default |
|---|---|---|
| `Sonarr__Auth__Method=Oidc` | `AuthenticationMethod` | `None` |
| `Sonarr__Auth__OidcAuthority` | `OidcAuthority` | empty |
| `Sonarr__Auth__OidcClientId` | `OidcClientId` | empty |
| `Sonarr__Auth__OidcClientSecret` | `OidcClientSecret` | empty |
| `Sonarr__Auth__OidcScopes` | `OidcScopes` | `openid profile email` |
| `Sonarr__Auth__OidcRequiredGroup` | `OidcRequiredGroup` | empty (no group check) |
| `Sonarr__Auth__OidcGroupsClaim` | `OidcGroupsClaim` | `groups` |
| `Sonarr__Auth__OidcUsernameClaim` | `OidcUsernameClaim` | `preferred_username` |

Redirect URI to register with the provider: `https://sonarr.media.sol.moe/signin-oidc`
(plus `/signout-callback-oidc`). Both honour `UrlBase`.

## Verified on a throwaway pod

| Case | Result |
|---|---|
| `method=None`, API without key | 401 |
| `method=None`, API with `X-Api-Key` | 200 |
| `initialize.json` contains `apiKey` | no (0 occurrences) |
| `method=Forms`, UI without cookie | 302 to `/login` |
| `method=Forms`, POST `/login` | 302 (session issued) |
| **API with session cookie, no key** | **200** |
| API with neither | 401 |
| API with key | 200 |
| `method=Oidc`, GET `/` and `/login` | 302 to the provider's authorize endpoint, `response_type=code`, PKCE `S256`, `response_mode=form_post`, nonce + state, `redirect_uri=.../signin-oidc` |
| `method=Oidc`, API without key | 401 (not redirected) |

Not yet exercised: the token exchange, claim mapping and the group check. Those
need a real provider; the wiring test used a public discovery document with a
dummy client id, which proves everything up to the redirect and no further.

## Three things that bit during implementation

1. **CodePages.** Referencing `Microsoft.AspNetCore.Authentication.OpenIdConnect`
   makes publish emit two copies of `System.Text.Encoding.CodePages` — the 8.0.0
   package one that MimeKit (via MailKit) requires and Host compiles against, and
   the runtime pack's older copy. `ErrorOnDuplicatePublishOutputFiles` is `false`
   upstream, so MSBuild silently picked the wrong one and the app died at startup
   with `FileLoadException`. Fixed with a target in `Directory.Build.props` that
   drops the runtime pack copy. Downgrading the pin instead does not work: MimeKit
   4.17 requires `>= 8.0.0` and NuGet fails with NU1605.
2. **The OIDC handler validates its options on every request** — it is an
   `IAuthenticationRequestHandler`, so it is constructed per request to check for
   the callback path. With no client id that validation throws and *every* request
   500s. The remote scheme is therefore registered only once configured, and
   `AuthenticationMethod` refuses to resolve to `Oidc` without a client id.
3. **BuildKit caches the `git clone` layer on the ref name**, so new commits on a
   branch are silently not rebuilt — two "fixes" appeared to change nothing.
   `Dockerfile.source` now takes `SONARR_SHA` and checks it out, which both busts
   the cache and makes builds reproducible. Always pass it.

## Authentik side (not done)

Create an OAuth2/OpenID provider + application, then:

- redirect URI `https://sonarr.media.sol.moe/signin-oidc`
- client type confidential, copy id/secret into a `Secret` in ns `media`
- if you want the group gate, add a scope mapping that emits `groups`, and set
  `Sonarr__Auth__OidcRequiredGroup` to the group name

## Deploying

Keep `arr-allowlist` on the IngressRoute: none of this closes the east-west path,
where any pod can still reach the ClusterIP with the API key.

Break-glass is `Sonarr__Auth__Method=Forms` on the Deployment, which overrides
config.xml. Confirm it works before switching the stored config.
