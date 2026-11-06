<?php
declare(strict_types=1);
namespace StellarSecurity\UserApiLaravel;
use Illuminate\Http\Client\Response;

/** Opt-in remembered desktop login; legacy session methods and retry behavior remain unchanged. */
class DesktopSessionClient extends UserService
{
    private function desktop(string $operation, #[\SensitiveParameter] array $body): Response
    {
        return $this->sessionClient()->post($this->baseUrl.'v1/desktop-session/'.$operation, $body);
    }
    public function loginRememberedSession(string $email, #[\SensitiveParameter] string $password): Response
    { return $this->desktop('login', ['username' => $email, 'password' => $password]); }
    public function registerRememberedSession(string $email, #[\SensitiveParameter] string $password): Response
    { return $this->desktop('register', ['username' => $email, 'password' => $password]); }
    public function rememberAnonymousSession(#[\SensitiveParameter] string $token, string $subscriptionHash): Response
    {
        if (!preg_match('/^[1-9][0-9]{0,31}\|[A-Za-z0-9]{40}$/D', $token) || !preg_match('/^[a-f0-9]{64}$/D', $subscriptionHash)) throw new \InvalidArgumentException('Invalid anonymous session.');
        return $this->desktop('anonymous', ['token' => $token, 'subscription_hash' => $subscriptionHash]);
    }
    public function renewDesktopSession(#[\SensitiveParameter] string $renewal): Response
    { $this->renewal($renewal); return $this->desktop('renew', ['renewal_token' => $renewal]); }
    public function logoutDesktopSession(#[\SensitiveParameter] string $renewal): Response
    { $this->renewal($renewal); return $this->desktop('logout', ['renewal_token' => $renewal]); }
    public function inspectDesktopSession(#[\SensitiveParameter] string $token): Response
    {
        if (!preg_match('/^[1-9][0-9]{0,31}\|[A-Za-z0-9]{40}$/D', $token)) throw new \InvalidArgumentException('Invalid session.');
        return $this->desktop('inspect', ['token' => $token]);
    }
    private function renewal(#[\SensitiveParameter] string $token): void
    {
        if (!preg_match('/^d1[a-f0-9]{32}\|[A-Za-z0-9]{64}$/D', $token)) throw new \InvalidArgumentException('Invalid device credential.');
    }
}
