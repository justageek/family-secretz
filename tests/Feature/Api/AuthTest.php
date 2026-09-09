<?php

namespace Tests\Feature\Api;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\Features;
use PragmaRX\Google2FA\Google2FA;
use Tests\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register_and_receives_access_token(): void
    {
        $response = $this->postJson('/api/register', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'password' => 'password',
            'password_confirmation' => 'password',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure(['access_token', 'token_type', 'user' => ['id', 'name', 'email']])
            ->assertJsonPath('user.email', 'jane@example.com');

        $this->assertDatabaseHas('users', ['email' => 'jane@example.com']);
    }

    public function test_user_can_login_and_receives_access_token(): void
    {
        $user = User::factory()->create(['password' => bcrypt('password')]);

        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['access_token', 'token_type', 'user'])
            ->assertJsonPath('user.email', $user->email)
            ->assertJsonMissingPath('requires_two_factor');
    }

    public function test_login_with_invalid_credentials_returns_validation_error(): void
    {
        $user = User::factory()->create(['password' => bcrypt('password')]);

        $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
        ])->assertStatus(422)->assertJsonValidationErrors('email');
    }

    public function test_login_with_two_factor_enabled_returns_login_token(): void
    {
        $this->skipUnlessTwoFactorEnabled();

        $user = $this->withTwoFactorAuthentication(
            User::factory()->create(['password' => bcrypt('password')])
        );

        $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->assertStatus(200)
            ->assertJsonPath('requires_two_factor', true)
            ->assertJsonPath('user.email', $user->email)
            ->assertJsonStructure(['login_token'])
            ->assertJsonMissingPath('access_token');
    }

    public function test_two_factor_challenge_exchanges_login_token_for_access_token(): void
    {
        $this->skipUnlessTwoFactorEnabled();

        $user = $this->withTwoFactorAuthentication(
            User::factory()->create(['password' => bcrypt('password')])
        );
        $loginToken = $this->loginAndGetLoginToken($user);

        $code = (new Google2FA)->getCurrentOtp(decrypt($user->two_factor_secret));

        $this->postJson('/api/two-factor-challenge', [
            'login_token' => $loginToken,
            'code' => $code,
        ])->assertStatus(200)
            ->assertJsonStructure(['access_token', 'token_type', 'user'])
            ->assertJsonPath('user.email', $user->email);
    }

    public function test_two_factor_challenge_with_invalid_code_returns_error(): void
    {
        $this->skipUnlessTwoFactorEnabled();

        $user = $this->withTwoFactorAuthentication(
            User::factory()->create(['password' => bcrypt('password')])
        );
        $loginToken = $this->loginAndGetLoginToken($user);

        $this->postJson('/api/two-factor-challenge', [
            'login_token' => $loginToken,
            'code' => '000000',
        ])->assertStatus(422)->assertJsonValidationErrors('code');
    }

    public function test_two_factor_challenge_with_recovery_code(): void
    {
        $this->skipUnlessTwoFactorEnabled();

        $user = User::factory()->create(['password' => bcrypt('password')]);
        $user->forceFill([
            'two_factor_secret' => encrypt(app(TwoFactorAuthenticationProvider::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['recovery-code-1', 'recovery-code-2'])),
            'two_factor_confirmed_at' => now(),
        ])->save();

        $loginToken = $this->loginAndGetLoginToken($user);

        $this->postJson('/api/two-factor-challenge', [
            'login_token' => $loginToken,
            'recovery_code' => 'recovery-code-1',
        ])->assertStatus(200)->assertJsonStructure(['access_token']);

        $user->refresh();
        $this->assertNotContains('recovery-code-1', $user->recoveryCodes());
    }

    public function test_two_factor_challenge_rejects_invalid_login_token(): void
    {
        $this->postJson('/api/two-factor-challenge', [
            'login_token' => '1|invalid-token',
            'code' => '123456',
        ])->assertStatus(422)->assertJsonValidationErrors('login_token');
    }

    public function test_user_endpoint_requires_authentication(): void
    {
        $this->getJson('/api/user')->assertStatus(401);
    }

    public function test_logout_revokes_the_current_token(): void
    {
        $user = User::factory()->create(['password' => bcrypt('password')]);

        $token = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->json('access_token');

        $this->withToken($token)->getJson('/api/user')->assertOk();

        $this->withToken($token)->postJson('/api/logout')
            ->assertOk()
            ->assertJsonPath('message', 'Logged out.');

        $this->withToken($token)->getJson('/api/user')->assertStatus(401);
    }

    public function test_user_can_list_and_revoke_tokens(): void
    {
        $user = User::factory()->create(['password' => bcrypt('password')]);

        $token = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->json('access_token');

        $user->createToken('other-device');

        $this->withToken($token)->getJson('/api/tokens')->assertOk()->assertJsonCount(2);

        $otherToken = $user->tokens()->where('name', 'other-device')->first();

        $this->withToken($token)->deleteJson("/api/tokens/{$otherToken->id}")
            ->assertOk()
            ->assertJsonPath('message', 'Token revoked.');

        $this->assertNull($user->tokens()->find($otherToken->id));
    }

    protected function skipUnlessTwoFactorEnabled(): void
    {
        if (! Features::enabled(Features::twoFactorAuthentication())) {
            $this->markTestSkipped('Two-factor authentication is disabled for the MVP.');
        }
    }

    protected function withTwoFactorAuthentication(User $user): User
    {
        $user->forceFill([
            'two_factor_secret' => encrypt(app(TwoFactorAuthenticationProvider::class)->generateSecretKey()),
            'two_factor_confirmed_at' => now(),
        ])->save();

        return $user;
    }

    protected function loginAndGetLoginToken(User $user): string
    {
        return $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password',
        ])->assertStatus(200)->json('login_token');
    }
}