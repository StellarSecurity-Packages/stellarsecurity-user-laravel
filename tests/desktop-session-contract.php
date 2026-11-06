<?php
declare(strict_types=1);
namespace Illuminate\Http\Client {
    class Response {}
    class PendingRequest {
        public static array $calls = [];
        public function post(string $url, array $body): Response { self::$calls[] = [$url,$body]; return new Response(); }
    }
}
namespace {
    require dirname(__DIR__).'/src/UserService.php';
    require dirname(__DIR__).'/src/DesktopSessionClient.php';
    $sdk = new class extends \StellarSecurity\UserApiLaravel\DesktopSessionClient {
        public function __construct() { $this->baseUrl='https://example.invalid/api/'; }
        protected function sessionClient(): \Illuminate\Http\Client\PendingRequest { return new \Illuminate\Http\Client\PendingRequest(); }
    };
    $token='42|'.str_repeat('a',40);$root='d1'.str_repeat('b',32).'|'.str_repeat('c',64);
    $sdk->loginRememberedSession('user@example.test','synthetic-password');
    $sdk->registerRememberedSession('user@example.test','synthetic-password');
    $sdk->rememberAnonymousSession($token,str_repeat('a',64));
    $sdk->rememberScopedSession($token);
    $sdk->renewDesktopSession($root);$sdk->inspectDesktopSession($token);$sdk->logoutDesktopSession($root);
    $expected=['login','register','anonymous','upgrade','renew','inspect','logout'];
    foreach (\Illuminate\Http\Client\PendingRequest::$calls as $i=>[$url,$body]) {
        if ($url!=='https://example.invalid/api/v1/desktop-session/'.$expected[$i] || str_contains($url,$root)) throw new \RuntimeException('Invalid SDK request');
    }
    foreach (['', $token, $root.'x'] as $bad) {
        try { $sdk->renewDesktopSession($bad); throw new \RuntimeException('Expected rejection'); } catch (\InvalidArgumentException) {}
    }
    if (count(\Illuminate\Http\Client\PendingRequest::$calls)!==7) throw new \RuntimeException('Unexpected request');
    echo "10 SDK contract checks passed; no framework boot, credentials or network.\n";
}
