<?php

declare(strict_types=1);

namespace StellarSecurity\UserApiLaravel;

use Illuminate\Http\Client\Response;

/** Opt-in remembered device login; legacy session methods and retry behavior remain unchanged. */
class DeviceSessionClient extends UserService
{
    private function device(string $operation, #[\SensitiveParameter] array $body): Response
    {
        return $this->sessionClient()->post($this->baseUrl . 'v1/device-sessions/' . $operation, $body);
    }

    public function loginRememberedSession(string $email, #[\SensitiveParameter] string $password): Response
    {
        return $this->device('login', ['username' => $email, 'password' => $password]);
    }

    public function registerRememberedSession(string $email, #[\SensitiveParameter] string $password): Response
    {
        return $this->device('register', ['username' => $email, 'password' => $password]);
    }

    public function rememberAnonymousSession(#[\SensitiveParameter] string $token, string $subscriptionHash): Response
    {
        if (
            ! preg_match('/^[1-9][0-9]{0,31}\|[A-Za-z0-9]{40}$/D', $token)
            || ! preg_match('/^[a-f0-9]{64}$/D', $subscriptionHash)
        ) {
            throw new \InvalidArgumentException('Invalid anonymous session.');
        }

        return $this->device('anonymous', ['token' => $token, 'subscription_hash' => $subscriptionHash]);
    }

    public function rememberScopedSession(#[\SensitiveParameter] string $token): Response
    {
        if (! preg_match('/^[1-9][0-9]{0,31}\|[A-Za-z0-9]{40}$/D', $token)) {
            throw new \InvalidArgumentException('Invalid session.');
        }

        return $this->device('upgrade', ['token' => $token]);
    }

    public function renewDeviceSession(#[\SensitiveParameter] string $renewal): Response
    {
        $this->renewal($renewal);

        return $this->device('renew', ['renewal_token' => $renewal]);
    }

    public function revokeDeviceSession(#[\SensitiveParameter] string $renewal): Response
    {
        $this->renewal($renewal);

        return $this->device('logout', ['renewal_token' => $renewal]);
    }

    public function inspectDeviceSession(#[\SensitiveParameter] string $token): Response
    {
        if (! preg_match('/^[1-9][0-9]{0,31}\|[A-Za-z0-9]{40}$/D', $token)) {
            throw new \InvalidArgumentException('Invalid session.');
        }

        return $this->device('inspect', ['token' => $token]);
    }

    private function renewal(#[\SensitiveParameter] string $token): void
    {
        if (! preg_match('/^d1[a-f0-9]{32}\|[A-Za-z0-9]{64}$/D', $token)) {
            throw new \InvalidArgumentException('Invalid device credential.');
        }
    }
}
