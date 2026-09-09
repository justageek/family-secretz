<?php

namespace Database\Seeders;

use App\Models\Account;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class AccountSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * Creates 3 test accounts, each with 1 account admin and 2 members.
     */
    public function run(): void
    {
        collect(['Smith Family', 'Johnson Family', 'Lee Family'])->each(function (string $accountName) {
            $slug = Str::slug($accountName);

            $account = Account::firstOrCreate(
                ['slug' => $slug],
                ['name' => $accountName],
            );

            $admin = User::factory()->create([
                'name' => "{$accountName} Admin",
                'email' => "admin@{$slug}.test",
                'account_id' => $account->id,
            ]);
            $admin->assignRole('account admin');

            collect(range(1, 2))->each(function (int $i) use ($account, $slug) {
                $member = User::factory()->create([
                    'name' => "{$account->name} Member {$i}",
                    'email' => "member{$i}@{$slug}.test",
                    'account_id' => $account->id,
                ]);
                $member->assignRole('member');
            });
        });
    }
}
