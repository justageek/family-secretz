<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('throttle:login')->post('/login', [AuthController::class, 'login']);
Route::middleware('throttle:two-factor')->post('/two-factor-challenge', [AuthController::class, 'twoFactorChallenge']);
Route::post('/register', [AuthController::class, 'register']);

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/tokens', [AuthController::class, 'tokens']);
    Route::delete('/tokens/{token}', [AuthController::class, 'revokeToken']);
});