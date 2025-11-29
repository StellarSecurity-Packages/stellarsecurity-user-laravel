<?php

namespace StellarSecurity\UserApiLaravel;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use GuzzleHttp\Promise\PromiseInterface;

/**
 * Strongly-typed service wrapper around the Stellar User API.
 *
 * This is designed for use inside Laravel apps:
 *
 *   use StellarSecurity\UserApiLaravel\UserService;
 *
 *   public function login(UserService $users) {
 *       $response = $users->auth([
 *           'email'    => 'foo@example.com',
 *           'password' => 'secret',
 *       ]);
 *   }
 *
 * All auth is done via HTTP Basic Auth using environment variables.
 */
class UserService
{
    /**
     * Base URL of the Stellar User API.
     * Example: https://stellaruserapiprod.azurewebsites.net/api/
     */
    protected string $baseUrl;

    /**
     * Name of the environment variable that holds the API username.
     */
    protected string $usernameEnvKey;

    /**
     * Name of the environment variable that holds the API password.
     */
    protected string $passwordEnvKey;

    public function __construct(?string $baseUrl = null)
    {
        // Allow override via config, otherwise fall back to hardcoded prod URL.
        $this->baseUrl = rtrim(
                $baseUrl ?: config('stellar-user.base_url', 'https://stellaruserapiprod.azurewebsites.net/api/'),
                '/'
            ) . '/';

        // Env variable names can be overridden via config.
        $this->usernameEnvKey = config(
            'stellar-user.username_env',
            'APPSETTING_API_USERNAME_STELLAR_USER_API'
        );

        $this->passwordEnvKey = config(
            'stellar-user.password_env',
            'APPSETTING_API_PASSWORD_STELLAR_USER_API'
        );
    }

    /**
     * Build a preconfigured HTTP client with basic auth + retry.
     */
    protected function client()
    {
        $username = env($this->usernameEnvKey);
        $password = env($this->passwordEnvKey);

        return Http::withBasicAuth($username, $password)
            ->retry(3);
    }

    /**
     * Create a new Stellar user.
     *
     * POST /v1/usercontroller/createuser
     */
    public function create(array $data): PromiseInterface|Response
    {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/createuser',
            $data
        );
    }

    /**
     * Send reset password link to a user.
     *
     * POST /v1/usercontroller/sendresetpasswordlink?email=...&confirmation_code=...
     */
    public function sendResetPasswordLink(string $email, string $confirmationCode): PromiseInterface|Response
    {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/sendresetpasswordlink',
            [
                // If backend expects query params only, you can switch to:
                // 'query' => ['email' => $email, 'confirmation_code' => $confirmationCode]
                'email'             => $email,
                'confirmation_code' => $confirmationCode,
            ]
        );
    }

    /**
     * Verify reset code and change password.
     *
     * POST /v1/usercontroller/verifyresetpasswordconfirmationcode
     */
    public function verifyResetPasswordConfirmationCode(
        string $email,
        string $confirmationCode,
        string $newPassword
    ): PromiseInterface|Response {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/verifyresetpasswordconfirmationcode',
            [
                'email'             => $email,
                'confirmation_code' => $confirmationCode,
                'new_password'      => $newPassword,
            ]
        );
    }

    /**
     * Patch/update user fields.
     *
     * PATCH /v1/usercontroller/patch
     */
    public function patch(array $data): PromiseInterface|Response
    {
        return $this->client()->patch(
            $this->baseUrl . 'v1/usercontroller/patch',
            $data
        );
    }

    /**
     * Authenticate user with email/password.
     *
     * POST /v1/usercontroller/login
     */
    public function auth(array $data): PromiseInterface|Response
    {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/login',
            $data
        );
    }

    /**
     * Fetch a user by ID.
     *
     * GET /v1/usercontroller/user/{id}
     */
    public function user(string $id): Response
    {
        return $this->client()->get(
            $this->baseUrl . 'v1/usercontroller/user/' . $id
        );
    }

    /**
     * Retrieve personal token information from the Stellar User API.
     *
     * @param  string  $token
     * @return \Illuminate\Http\Client\Response
     */
    public function token(string $token): Response
    {
        return $this->client()->get(
            $this->baseUrl . 'v1/personaltokencontroller/' . $token
        );
    }

}
