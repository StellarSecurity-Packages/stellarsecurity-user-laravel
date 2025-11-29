<?php

namespace StellarSecurity\UserApiLaravel;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\Client\Response;
use GuzzleHttp\Promise\PromiseInterface;

/**
 * UserApiClient is a small wrapper around the external Stellar User API.
 *
 * It centralises:
 * - base URL
 * - basic authentication credentials
 * - retry behaviour
 *
 * You can type-hint this class in your controllers/services and rely on
 * Laravel's container to inject it automatically.
 */
class UserApiClient
{
    /**
     * Base URL of the Stellar User API.
     *
     * @var string
     */
    protected string $baseUrl;

    /**
     * Name of the environment variable that holds the username.
     *
     * @var string
     */
    protected string $usernameEnvKey;

    /**
     * Name of the environment variable that holds the password.
     *
     * @var string
     */
    protected string $passwordEnvKey;

    public function __construct()
    {
        $this->baseUrl = rtrim(config('stellar-user.base_url', 'https://stellaruserapiprod.azurewebsites.net/api/'), '/') . '/';

        // These keys tell us which env variables actually contain the secrets.
        $this->usernameEnvKey = config('stellar-user.username_env_key', 'APPSETTING_API_USERNAME_STELLAR_USER_API');
        $this->passwordEnvKey = config('stellar-user.password_env_key', 'APPSETTING_API_PASSWORD_STELLAR_USER_API');
    }

    /**
     * Resolve the username from environment.
     */
    protected function username(): ?string
    {
        $key = $this->usernameEnvKey;

        return $key ? getenv($key) ?: null : null;
    }

    /**
     * Resolve the password from environment.
     */
    protected function password(): ?string
    {
        $key = $this->passwordEnvKey;

        return $key ? getenv($key) ?: null : null;
    }

    /**
     * Build a base HTTP client with basic auth + retry configured.
     */
    protected function client()
    {
        $username = $this->username();
        $password = $this->password();

        $request = Http::retry(3, 200);

        if ($username !== null && $password !== null) {
            $request = $request->withBasicAuth($username, $password);
        }

        return $request;
    }

    /**
     * Create a new user in the Stellar User API.
     *
     * Expected payload structure is defined by the upstream API.
     *
     * @param array<string,mixed> $data
     * @return PromiseInterface|Response
     */
    public function create(array $data): PromiseInterface|Response
    {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/createuser',
            $data
        );
    }

    /**
     * Send a reset-password link to the given email.
     *
     * @param string $email
     * @param string $confirmationCode
     * @return PromiseInterface|Response
     */
    public function sendResetPasswordLink(string $email, string $confirmationCode): PromiseInterface|Response
    {
        $url = $this->baseUrl . 'v1/usercontroller/sendresetpasswordlink';

        return $this->client()->post($url, [
            'email' => $email,
            'confirmation_code' => $confirmationCode,
        ]);
    }

    /**
     * Verify a reset-password confirmation code and set the new password.
     *
     * @param string $email
     * @param string $confirmationCode
     * @param string $newPassword
     * @return PromiseInterface|Response
     */
    public function verifyResetPasswordConfirmationCode(
        string $email,
        string $confirmationCode,
        string $newPassword
    ): PromiseInterface|Response {
        $url = $this->baseUrl . 'v1/usercontroller/verifyresetpasswordconfirmationcode';

        return $this->client()->post($url, [
            'email' => $email,
            'confirmation_code' => $confirmationCode,
            'new_password' => $newPassword,
        ]);
    }

    /**
     * Patch / update an existing user in the Stellar User API.
     *
     * @param array<string,mixed> $data
     * @return PromiseInterface|Response
     */
    public function patch(array $data): PromiseInterface|Response
    {
        $url = $this->baseUrl . 'v1/usercontroller/patch';

        return $this->client()->patch($url, $data);
    }

    /**
     * Authenticate a user against the Stellar User API.
     *
     * Typical payload: ['email' => '...', 'password' => '...']
     *
     * @param array<string,mixed> $data
     * @return PromiseInterface|Response
     */
    public function auth(array $data): PromiseInterface|Response
    {
        $url = $this->baseUrl . 'v1/usercontroller/login';

        return $this->client()->post($url, $data);
    }

    /**
     * Fetch a user by ID from the Stellar User API.
     *
     * @param string $id
     * @return Response
     */
    public function user(string $id): Response
    {
        $url = $this->baseUrl . 'v1/usercontroller/user/' . $id;

        return $this->client()->get($url);
    }
}
