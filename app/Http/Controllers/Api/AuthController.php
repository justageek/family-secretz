<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\Events\TwoFactorAuthenticationFailed;
use Laravel\Fortify\Events\ValidTwoFactorAuthenticationCodeProvided;
use Laravel\Fortify\Features;
use Laravel\Fortify\Fortify;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    /**
     * How long a pending two-factor login token stays valid (minutes).
     */
    protected const TWO_FACTOR_TOKEN_TTL = 10;

    /**
     * Register a new user and return a Sanctum access token.
     */
    public function register(Request $request): JsonResponse
    {
        $user = app(CreatesNewUsers::class)->create($request->all());

        return $this->tokenResponse($user, 201);
    }

    /**
     * Authenticate a user and return a Sanctum access token.
     *
     * If the user has two-factor authentication enabled, a short-lived
     * "two-factor" login token is returned instead so the client can
     * complete the challenge at POST /api/two-factor-challenge.
     */
    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where(Fortify::username(), $request->input(Fortify::username()))->first();

        if (! $user || ! Hash::check($request->input('password'), $user->password)) {
            throw ValidationException::withMessages([
                Fortify::username() => [trans('auth.failed')],
            ]);
        }

        if (Features::enabled(Features::twoFactorAuthentication()) && $user->hasEnabledTwoFactorAuthentication()) {
            $loginToken = $user->createToken(
                'two-factor-login',
                ['two-factor'],
                now()->addMinutes(self::TWO_FACTOR_TOKEN_TTL),
            );

            return response()->json([
                'requires_two_factor' => true,
                'login_token' => $loginToken->plainTextToken,
                'user' => $user,
            ]);
        }

        return $this->tokenResponse($user);
    }

    /**
     * Complete a two-factor challenge started at POST /api/login.
     *
     * Accepts the short-lived "two-factor" login token plus either a
     * TOTP "code" or a "recovery_code", and exchanges them for a full
     * Sanctum access token.
     */
    public function twoFactorChallenge(Request $request): JsonResponse
    {
        $request->validate([
            'login_token' => ['required', 'string'],
            'code' => ['required_without:recovery_code', 'nullable', 'string'],
            'recovery_code' => ['required_without:code', 'nullable', 'string'],
        ]);

        $token = PersonalAccessToken::findToken($request->input('login_token'));

        if (! $token || in_array('*', $token->abilities, true) || ! $token->can('two-factor') || $token->expires_at?->isPast()) {
            throw ValidationException::withMessages([
                'login_token' => ['The login token is invalid or has expired.'],
            ]);
        }

        $user = $token->tokenable;

        if ($request->filled('recovery_code')) {
            $code = collect($user->recoveryCodes())->first(
                fn (string $code) => hash_equals($code, $request->input('recovery_code')),
            );

            if (! $code) {
                event(new TwoFactorAuthenticationFailed($user));

                throw ValidationException::withMessages([
                    'recovery_code' => ['The provided recovery code was invalid.'],
                ]);
            }

            $user->replaceRecoveryCode($code);
        } elseif (! app(TwoFactorAuthenticationProvider::class)->verify(
            decrypt($user->two_factor_secret),
            $request->input('code'),
        )) {
            event(new TwoFactorAuthenticationFailed($user));

            throw ValidationException::withMessages([
                'code' => ['The provided two factor authentication code was invalid.'],
            ]);
        }

        event(new ValidTwoFactorAuthenticationCodeProvided($user));

        $token->delete();

        return $this->tokenResponse($user);
    }

    /**
     * Revoke the access token used for the current request.
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out.']);
    }

    /**
     * List the user's active access tokens (device management).
     */
    public function tokens(Request $request)
    {
        return $request->user()->tokens()->get();
    }

    /**
     * Revoke a specific access token belonging to the user.
     */
    public function revokeToken(Request $request, string $tokenId): JsonResponse
    {
        $request->user()->tokens()->whereKey($tokenId)->delete();

        return response()->json(['message' => 'Token revoked.']);
    }

    /**
     * Create a new Sanctum token and format the login response.
     */
    protected function tokenResponse(User $user, int $status = 200): JsonResponse
    {
        $token = $user->createToken('mobile');

        return response()->json([
            'access_token' => $token->plainTextToken,
            'token_type' => 'Bearer',
            'expires_at' => $token->accessToken->expires_at?->toISOString(),
            'user' => $user,
        ], $status);
    }
}