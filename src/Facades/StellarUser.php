<?php

namespace StellarSecurity\UserApiLaravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response create(array $data)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response sendResetPasswordLink(string $email, string $confirmationCode)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response verifyResetPasswordConfirmationCode(string $email, string $confirmationCode, string $newPassword)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response changePassword(string $userId, string $currentPassword, string $newPassword)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response deleteUser(int|string $userId, string $currentPassword)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response patch(array $data)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response auth(array $data)
 * @method static \Illuminate\Http\Client\Response user(string $id)
 * @method static \Illuminate\Http\Client\Response loginSession(string $email, string $password, ?\DateTimeInterface $expiresAt = null)
 * @method static \Illuminate\Http\Client\Response registerSession(string $email, string $password, ?\DateTimeInterface $expiresAt = null)
 * @method static \Illuminate\Http\Client\Response introspectSession(string $token)
 * @method static \Illuminate\Http\Client\Response logoutSession(string $token)
 *
 * @see \StellarSecurity\UserApiLaravel\UserApiClient
 */
class StellarUser extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'stellar.user';
    }
}
