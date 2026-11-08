<?php

declare(strict_types=1);

namespace Illuminate\Http\Client {
    class Response
    {
    }
    class PendingRequest
    {
        public static array $calls = [];

        public function post(string $url, array $body): Response
        {
            self::$calls[] = [$url, $body];

            return new Response();
        }
    }
}
namespace {
    require dirname(__DIR__) . '/src/UserService.php';
    require dirname(__DIR__) . '/src/DeviceSessionClient.php';
    $sdk = new class extends \StellarSecurity\UserApiLaravel\DeviceSessionClient
    {
        public function __construct()
        {
            $this->baseUrl = 'https://example.invalid/api/';
        }

        protected function sessionClient(): \Illuminate\Http\Client\PendingRequest
        {
            return new \Illuminate\Http\Client\PendingRequest();
        }
    };
    $token = '42|' . str_repeat('a', 40);
    $root = 'd1' . str_repeat('b', 32) . '|' . str_repeat('c', 64);
    $sdk->loginRememberedSession('user@example.test', 'synthetic-password');
    $sdk->registerRememberedSession('user@example.test', 'synthetic-password');
    $sdk->rememberAnonymousSession($token, str_repeat('a', 64));
    try {
        $sdk->rememberScopedSession($token);
        throw new \RuntimeException('Access-only enrollment must not issue a request');
    } catch (\LogicException) {
    }
    $sdk->listDeviceSessions($root);
    $sdk->listDeviceSessions($root, explode('|', $root)[0]);
    $sdk->revokeOwnedDeviceSession($root, explode('|', $root)[0]);
    $sdk->renewDeviceSession($root);
    $sdk->inspectDeviceSession($token);
    $sdk->revokeDeviceSession($root);
    $expected = [
        'login',
        'register',
        'anonymous',
        'list',
        'list',
        'revoke-owned',
        'renew',
        'inspect',
        'logout',
    ];
    foreach (\Illuminate\Http\Client\PendingRequest::$calls as $i => [$url, $body]) {
        if (
            $url !== 'https://example.invalid/api/v1/device-sessions/' . $expected[$i]
            || str_contains($url, $root)
        ) {
            throw new \RuntimeException('Invalid SDK request');
        }
    }
    foreach (['', $token, $root . 'x'] as $bad) {
        try {
            $sdk->renewDeviceSession($bad);
            throw new \RuntimeException('Expected rejection');
        } catch (\InvalidArgumentException) {
        }
    }
    if (count(\Illuminate\Http\Client\PendingRequest::$calls) !== 9) {
        throw new \RuntimeException('Unexpected request');
    }
    $calls = \Illuminate\Http\Client\PendingRequest::$calls;
    if ($calls[3][1] !== ['renewal_token' => $root]
        || $calls[4][1] !== ['renewal_token' => $root, 'after' => explode('|', $root)[0]]
        || $calls[5][1] !== ['renewal_token' => $root, 'session_id' => explode('|', $root)[0]]) {
        throw new \RuntimeException('Invalid management payload');
    }
    foreach (['', '../invalid', $root,  'd1' . str_repeat('a', 33)] as $badId) {
        foreach (['listDeviceSessions', 'revokeOwnedDeviceSession'] as $method) {
            try {
                $sdk->{$method}($root, $badId);
                throw new \RuntimeException('Invalid identifier accepted');
            } catch (\InvalidArgumentException) {
            }
        }
    }
    if (count(\Illuminate\Http\Client\PendingRequest::$calls) !== 9) {
        throw new \RuntimeException('Invalid input reached transport');
    }
    require dirname(__DIR__) . '/src/DesktopSessionClient.php';
    $compat = new class extends \StellarSecurity\UserApiLaravel\DesktopSessionClient
    {
        public function __construct()
        {
            $this->baseUrl = 'https://example.invalid/api/';
        }

        protected function sessionClient(): \Illuminate\Http\Client\PendingRequest
        {
            return new \Illuminate\Http\Client\PendingRequest();
        }
    };
    $compat->renewDesktopSession($root);
    $compat->logoutDesktopSession($root);
    $compat->inspectDesktopSession($token);
    foreach (array_slice(\Illuminate\Http\Client\PendingRequest::$calls, 9) as[$url, $body]) {
        if (! str_starts_with($url, 'https://example.invalid/api/v1/device-sessions/')) {
            throw new \RuntimeException('Compatibility alias escaped shared protocol');
        }
    }
    echo "21 SDK contract checks passed; no framework boot, credentials or network.\n";
}
