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
        // Preserve explicitly configured legacy keys; also honor the published config.
        $this->usernameEnvKey = config('stellar-user.username_env')
            ?? config('stellar-user.username_env_key', 'APPSETTING_API_USERNAME_STELLAR_USER_API');

        $this->passwordEnvKey = config('stellar-user.password_env')
            ?? config('stellar-user.password_env_key', 'APPSETTING_API_PASSWORD_STELLAR_USER_API');
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

    /** Separate transport: legacy retry/response behavior above remains unchanged. */
    protected function sessionClient(): \Illuminate\Http\Client\PendingRequest
    {
        $url = parse_url($this->baseUrl);
        if ($url === false || ($url['scheme'] ?? '') !== 'https' || empty($url['host'])
            || isset($url['user']) || isset($url['pass'])
            || isset($url['query']) || isset($url['fragment'])) {
            throw new \InvalidArgumentException('Session requests require an HTTPS API base URL without embedded credentials.');
        }
        $username = env($this->usernameEnvKey);
        $password = env($this->passwordEnvKey);
        if (!is_string($username) || $username === '' || !is_string($password) || $password === '') {
            throw new \RuntimeException('User API service authentication is not configured.');
        }
        return Http::withBasicAuth($username, $password)->acceptJson()->asJson()
            ->connectTimeout(5)->timeout(15)
            ->withOptions(['allow_redirects' => false, 'http_errors' => false, 'verify' => true]);
    }

    /** Login without rotating legacy sessions. Omitted expiry uses the API's 24h default. */
    public function loginSession(string $email, #[\SensitiveParameter] string $password, ?\DateTimeInterface $expiresAt = null): Response
    {
        return $this->sessionClient()->post($this->baseUrl.'v1/sessioncontroller/login',
            $this->sessionCredentials($email, $password, $expiresAt));
    }

    /** Separate scoped registration. Existing create() behavior is unchanged. */
    public function registerSession(string $email, #[\SensitiveParameter] string $password, ?\DateTimeInterface $expiresAt = null): Response
    {
        return $this->sessionClient()->post($this->baseUrl.'v1/sessioncontroller/register',
            $this->sessionCredentials($email, $password, $expiresAt));
    }

    /** Never place a scoped bearer token in the URL. */
    public function introspectSession(#[\SensitiveParameter] string $token): Response
    {
        $this->validateSessionToken($token);
        return $this->sessionClient()->post($this->baseUrl.'v1/sessioncontroller/introspect', ['token' => $token]);
    }

    /** Revoke only the supplied scoped session. */
    public function logoutSession(#[\SensitiveParameter] string $token): Response
    {
        $this->validateSessionToken($token);
        return $this->sessionClient()->post($this->baseUrl.'v1/sessioncontroller/logout', ['token' => $token]);
    }

    public function deleteAccount(#[\SensitiveParameter] string $accessToken, #[\SensitiveParameter] string $currentPassword): Response
    {
        if (! preg_match('/^(?:[1-9][0-9]{0,19}\|)?[A-Za-z0-9]{40}$/D', $accessToken)) {
            throw new \InvalidArgumentException('Invalid account access token.');
        }

        return $this->sessionClient()->post($this->baseUrl.'v1/usercontroller/deleteuser', [
            'access_token' => $accessToken,
            'current_password' => $currentPassword,
        ]);
    }

    public function startOpaqueLogin(string $email, #[\SensitiveParameter] string $startLoginRequest): Response
    {
        if (strlen($email) > 254 || ! filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
            throw new \InvalidArgumentException('Invalid OPAQUE email.');
        }
        $this->validateOpaqueProof($startLoginRequest);

        return $this->sessionClient()->post($this->baseUrl.'v2/auth/start', [
            'email' => $email,
            'startLoginRequest' => $startLoginRequest,
        ]);
    }

    public function finishOpaqueLogin(string $challengeId, #[\SensitiveParameter] string $finishLoginRequest): Response
    {
        if (! preg_match('/^[a-f0-9]{64}$/D', $challengeId)) {
            throw new \InvalidArgumentException('Invalid OPAQUE challenge.');
        }
        $this->validateOpaqueProof($finishLoginRequest);

        return $this->sessionClient()->post($this->baseUrl.'v2/auth/finish', [
            'challengeId' => $challengeId,
            'finishLoginRequest' => $finishLoginRequest,
        ]);
    }

    public function inspectOpaqueSession(#[\SensitiveParameter] string $token): Response
    {
        $this->validateSessionToken($token);

        return $this->sessionClient()->post($this->baseUrl.'v2/auth/session', ['token' => $token]);
    }

    public function logoutOpaqueSession(#[\SensitiveParameter] string $token): Response
    {
        $this->validateSessionToken($token);

        return $this->sessionClient()->post($this->baseUrl.'v2/auth/logout', ['token' => $token]);
    }

    public function startOpaqueAccount(string $flow, #[\SensitiveParameter] array $body): Response
    {
        return $this->opaqueAccountRequest($flow, 'start', $body);
    }

    public function proveOpaqueAccount(string $flow, #[\SensitiveParameter] array $body): Response
    {
        return $this->opaqueAccountRequest($flow, 'prove', $body);
    }

    public function finishOpaqueAccount(string $flow, #[\SensitiveParameter] array $body): Response
    {
        return $this->opaqueAccountRequest($flow, 'finish', $body);
    }

    private function opaqueAccountRequest(string $flow, string $step, #[\SensitiveParameter] array $body): Response
    {
        if (! in_array($flow, ['register', 'enroll', 'password', 'recovery-setup', 'recover', 'delete'], true)
            || ($flow === 'delete' && $step === 'prove')) {
            throw new \InvalidArgumentException('Invalid OPAQUE account operation.');
        }
        $expected = match ($step) {
            'start' => match ($flow) {
                'register' => ['email', 'registrationRequest'],
                'enroll' => ['token', 'registrationRequest'],
                'delete' => ['token', 'authorizationRequest'],
                'recover' => ['accountId', 'email', 'registrationRequest', 'authorizationRequest'],
                default => ['token', 'registrationRequest', 'authorizationRequest'],
            },
            'prove' => in_array($flow, ['register', 'enroll'], true)
                ? ['challengeId', 'registrationRecord', 'startLoginRequest', 'keyEnvelope']
                : ['challengeId', 'registrationRecord', 'startLoginRequest', 'keyEnvelope', 'authorizationFinish', 'authorizationProof'],
            'finish' => $flow === 'delete'
                ? ['challengeId', 'authorizationFinish', 'authorizationProof']
                : ['challengeId', 'finishLoginRequest', 'commitProof'],
        };
        $actual = array_keys($body);
        sort($actual);
        sort($expected);
        if ($actual !== $expected) {
            throw new \InvalidArgumentException('Invalid OPAQUE account fields.');
        }
        foreach ($body as $field => $value) {
            if (! is_string($value) || $value === '' || strlen($value) > 16384) {
                throw new \InvalidArgumentException('Invalid OPAQUE account value.');
            }
            if ($field === 'token') {
                $this->validateSessionToken($value);
            } elseif ($field === 'challengeId' && ! preg_match('/^[a-f0-9]{64}$/D', $value)) {
                throw new \InvalidArgumentException('Invalid OPAQUE account challenge.');
            } elseif ($field === 'accountId' && ! preg_match('/^[1-9][0-9]{0,19}$/D', $value)) {
                throw new \InvalidArgumentException('Invalid OPAQUE account ID.');
            } elseif ($field === 'email' && (strlen($value) > 254 || ! filter_var(trim($value), FILTER_VALIDATE_EMAIL))) {
                throw new \InvalidArgumentException('Invalid OPAQUE account email.');
            } elseif (in_array($field, ['keyEnvelope', 'authorizationProof', 'commitProof'], true)) {
                $bytes = base64_decode($value, true);
                if ($bytes === false || strlen($bytes) !== ($field === 'keyEnvelope' ? 60 : 32)
                    || base64_encode($bytes) !== $value) {
                    throw new \InvalidArgumentException('Invalid OPAQUE envelope or proof.');
                }
            }
        }

        return $this->sessionClient()->post($this->baseUrl.'v2/auth/account/'.$flow.'/'.$step, $body);
    }

    private function validateOpaqueProof(#[\SensitiveParameter] string $proof): void
    {
        if ($proof === '' || strlen($proof) > 16384) {
            throw new \InvalidArgumentException('Invalid OPAQUE message.');
        }
    }

    private function sessionCredentials(string $email, #[\SensitiveParameter] string $password, ?\DateTimeInterface $expiresAt): array
    {
        $fields = ['username' => $email, 'password' => $password];
        if ($expiresAt !== null) $fields['expires_at'] = $expiresAt->format(DATE_ATOM);
        return $fields;
    }

    private function validateSessionToken(#[\SensitiveParameter] string $token): void
    {
        if (strlen($token) > 256 || !preg_match('/^[1-9][0-9]*\|[A-Za-z0-9]{40}$/D', $token)) {
            throw new \InvalidArgumentException('Invalid scoped session token.');
        }
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
     * The confirmationCode argument requests email-code delivery for compatibility.
     * User API generates the actual code; verify the code received by email.
     * Protected OPAQUE accounts use the account recovery flow instead.
     *
     * POST /v1/usercontroller/sendresetpasswordlink
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
     * Checks reset code only
     *
     * POST /v1/usercontroller/checkresetpasswordconfirmationcode
     */
    public function checkresetpasswordconfirmationcode(
        string $email,
        string $confirmationCode
    ): PromiseInterface|Response {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/checkresetpasswordconfirmationcode',
            [
                'email'             => $email,
                'confirmation_code' => $confirmationCode
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

    /**
     * Change a user's password.
     *
     * PATCH /v1/usercontroller/changepassword
     */
    public function changePassword(
        int $userId,
        string $currentPassword,
        string $newPassword
    ): PromiseInterface|Response {
        return $this->client()->patch(
            $this->baseUrl . 'v1/usercontroller/changepassword',
            [
                'user_id'          => $userId,
                'current_password' => $currentPassword,
                'new_password'     => $newPassword,
            ]
        );
    }

    /**
     * Delete a user.
     *
     * POST /v1/usercontroller/deleteuser
     */
    public function deleteUser(
        int|string $userId,
        string $currentPassword
    ): PromiseInterface|Response {
        return $this->client()->post(
            $this->baseUrl . 'v1/usercontroller/deleteuser',
            [
                'user_id'          => $userId,
                'current_password' => $currentPassword,
            ]
        );
    }

}
