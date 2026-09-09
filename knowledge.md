# Project Knowledge

## What this is
Laravel 13 (PHP ^8.3) **authentication backend for a mobile app UI**, consumed as a JSON API (no server-rendered auth pages — `config/fortify.php` has `views => false`). OAuth integration is planned but **not yet implemented** (user will wire it up later).

## Auth stack
- **Fortify ^1.38** — headless auth: registration, login, password reset, profile/password update, passkeys. All routes + rate limiters registered via `app/Providers/FortifyServiceProvider.php`. **2FA is disabled for the MVP** — the `twoFactorAuthentication` feature is commented out in `config/fortify.php`; the API challenge code (`AuthController::twoFactorChallenge`, `two-factor` limiter, 2FA tests) stays in place and activates when the feature is re-enabled.
- **Sanctum ^4.0** — mobile/token auth endpoints in `routes/api.php` (`login`, `register`, `two-factor-challenge`, `logout`, `tokens`) handled by `app/Http/Controllers/Api/AuthController.php`; `HasApiTokens` on User.
- **laravel/passkeys** (WebAuthn, pulled in by Fortify) — `passkeys/` and `user/passkeys/` routes; routes come through Fortify (passkeys' own routes are disabled by `FortifyServiceProvider::configurePasskeys()`).

### Key files
- `app/Actions/Fortify/*` — CreateNewUser, PasswordValidationRules, ResetUserPassword, UpdateUserPassword, UpdateUserProfileInformation.
- `app/Models/User.php` — **must keep** `TwoFactorAuthenticatable`, `PasskeyAuthenticatable` traits and `implements PasskeyUser` (2FA + passkey controllers throw at runtime without them). Uses PHP attributes `#[Fillable([...])]`, `#[Hidden([...])]` instead of class properties.
- `config/fortify.php`, `config/sanctum.php` — features, limiters (`login` 5/min, `two-factor` 5/min, `passkeys` 10/min).
- `bootstrap/app.php` — Laravel 11+ slim skeleton: routing (web/api/commands, health `/up`), middleware config here (no Http Kernel), JSON errors for `api/*` / `expectsJson()`.
- Migrations: users/password_reset_tokens/sessions, two_factor columns, passkeys, personal_access_tokens.

### Auth endpoints (session-based, `web` middleware, CSRF-protected)
`POST /login`, `POST /register`, `POST /logout`, `POST /forgot-password`, `POST /reset-password`, `POST /two-factor-challenge`, `PUT /user/profile-information`, `PUT /user/password`, passkey routes (`/passkeys/*`, `/user/passkeys*`), `GET /sanctum/csrf-cookie`.

### Token endpoints (mobile clients, `api` middleware, Bearer token)
- `POST /api/login` (`email`, `password`) → `{ access_token, token_type, expires_at, user }`. (With the 2FA feature on, users with 2FA get `{ requires_two_factor: true, login_token, user }` instead — dormant for MVP.)
- `POST /api/two-factor-challenge` (`login_token` + `code` or `recovery_code`) → exchanges the short-lived `two-factor` token (10 min TTL) for a full access token; temp token is revoked on success. (Dormant for MVP.)
- `POST /api/register` (`name`, `email`, `password`, `password_confirmation`) → 201 with access token.
- `POST /api/logout` (auth) → revokes the current token. `GET /api/tokens` / `DELETE /api/tokens/{id}` (auth) → device management.
- Login is throttled by the `login` limiter (5/min), the 2FA challenge by `two-factor` (5/min).

## Commands
```bash
# Setup
composer install && cp .env.example .env && php artisan key:generate && php artisan migrate

# Dev (starts vite + server via composer script)
composer dev            # or: php artisan dev

# Tests (PHPUnit 12)
composer test           # or: php artisan test

# Lint / format
vendor/bin/pint

# Frontend
npm run dev / npm run build
```

## Environment: Laravel Sail + PostgreSQL
Primary dev path is **Sail** (`compose.yaml`): PHP 8.5 runtime + Postgres 17 container. `./vendor/bin/sail up -d`, then prefix commands with `sail` (e.g. `sail artisan test`). Note: `compose.yaml` uses Postgres while `.env.example` ships `DB_CONNECTION=sqlite` — set proper `DB_*` values when using Sail.

## Gotchas
- **Sandbox/CI PHP lacks PDO** — artisan commands that boot the DB fail with `Class "PDO" not found`. Workaround for boot-level checks: `CACHE_STORE=array SESSION_DRIVER=array php artisan route:list`.
- **No auth Blade views exist** (only `welcome.blade.php`) and `views => false` is intentional — don't "fix" by re-enabling views; GET auth pages 404 by design.
- `config/fortify.php` `home => '/home'` — no such route exists; bind a custom LoginResponse for API/mobile before relying on post-login redirects.
- Passkeys `relying_party_id`/`allowed_origins` derive from `APP_URL` — must match the client origin in any deployed environment.
- Sanctum `stateful` domains default to localhost only — set `SANCTUM_STATEFUL_DOMAINS` for deployed SPA use.
- 2FA disabled for MVP (`config/fortify.php`) — the API login branch additionally guards on `Features::enabled(...)`, so config is the single source of truth. Re-enable = uncomment the feature; the `two-factor` rate limiter falls back to the `login_token`/bearer token when there's no session (`login.id`), and the 2FA tests un-skip.

## Conventions
- Slim Laravel 13 skeleton: providers in `bootstrap/providers.php`, middleware/exceptions in `bootstrap/app.php`.
- Validation in Fortify actions via `Validator::make(...)`; passwords via `Password::default()` + `confirmed`.
- Tests live in `tests/Feature` + `tests/Unit` — token auth covered by `tests/Feature/Api/AuthTest.php` (register/login/logout/tokens + 2FA challenge with TOTP and recovery codes; 2FA tests auto-skip via `skipUnlessTwoFactorEnabled()` while the feature is off).
