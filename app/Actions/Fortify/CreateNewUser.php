<?php

namespace App\Actions\Fortify;

use App\Models\Account;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Spatie\Permission\Models\Role;

class CreateNewUser implements CreatesNewUsers
{
    use PasswordValidationRules;

    /**
     * Validate and create a newly registered user, along with the new
     * account (tenant) they administer.
     *
     * @param  array<string, string>  $input
     *
     * @throws ValidationException
     */
    public function create(array $input): User
    {
        Validator::make($input, [
            'name' => ['required', 'string', 'max:255'],
            'account_name' => ['required', 'string', 'max:255'],
            'email' => [
                'required',
                'string',
                'email',
                'max:255',
                Rule::unique(User::class),
            ],
            'password' => $this->passwordRules(),
        ])->validate();

        return DB::transaction(function () use ($input) {
            $account = Account::create([
                'name' => $input['account_name'],
                'slug' => $this->uniqueSlug($input['account_name']),
            ]);

            $user = User::create([
                'name' => $input['name'],
                'email' => $input['email'],
                'password' => Hash::make($input['password']),
                'account_id' => $account->id,
            ]);

            $user->assignRole(Role::firstOrCreate(['name' => 'account admin']));

            return $user->setRelation('account', $account);
        });
    }

    /**
     * Slugify the account name, appending a numeric suffix on collision.
     */
    protected function uniqueSlug(string $name): string
    {
        $slug = Str::slug($name);
        $unique = $slug;
        $suffix = 1;

        while (Account::where('slug', $unique)->exists()) {
            $unique = "{$slug}-{$suffix}";
            $suffix++;
        }

        return $unique;
    }
}
