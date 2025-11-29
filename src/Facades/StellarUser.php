<?php

namespace StellarSecurity\UserApiLaravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response create(array $data)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response sendResetPasswordLink(string $email, string $confirmationCode)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response verifyResetPasswordConfirmationCode(string $email, string $confirmationCode, string $newPassword)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response patch(array $data)
 * @method static \GuzzleHttp\Promise\PromiseInterface|\Illuminate\Http\Client\Response auth(array $data)
 * @method static \Illuminate\Http\Client\Response user(string $id)
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
