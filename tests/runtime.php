<?php
declare(strict_types=1);
// Requires explicit approval of this exact source before executing the package.
if (getenv('STELLAR_USER_PACKAGE_RUNTIME_REVIEW') !== '1' || getenv('APP_ENV') !== 'testing' || count($argv) !== 2) {
    fwrite(STDERR, "Approved runtime test mode and existing reviewed Laravel autoload path required.\n"); exit(1);
}
require $argv[1];
$root = dirname(__DIR__);
spl_autoload_register(static function (string $class) use ($root): void {
    $prefix = 'StellarSecurity\\UserApiLaravel\\';
    if (str_starts_with($class, $prefix)) {
        $path = $root.'/src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
        if (is_file($path)) require $path;
    }
});

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Http;
use StellarSecurity\UserApiLaravel\StellarUserServiceProvider;
use StellarSecurity\UserApiLaravel\UserApiClient;
use StellarSecurity\UserApiLaravel\UserService;
use StellarSecurity\UserApiLaravel\Facades\StellarUser;

$app = new Application($root);
$app->instance('config', new Repository(['stellar-user' => ['base_url' => 'https://identity.example.test/api/',
    'username_env_key' => 'STELLAR_PACKAGE_TEST_USERNAME', 'password_env_key' => 'STELLAR_PACKAGE_TEST_PASSWORD']]));
Facade::setFacadeApplication($app);
putenv('STELLAR_PACKAGE_TEST_USERNAME=synthetic-service');
putenv('STELLAR_PACKAGE_TEST_PASSWORD=synthetic-password');
$factory = new class extends Factory
{
    protected function newPendingRequest()
    {
        return parent::newPendingRequest()->setHandler(fn () => throw new LogicException('Real HTTP is blocked.'));
    }
};
$factory->preventStrayRequests();
$optionsSeen = [];
$factory->fake(function ($request, $options) use ($factory, &$optionsSeen) {
    $optionsSeen[] = $options;
    return $factory->response(['response_code' => 401, 'error' => 'invalid_credentials'], 401);
});
Http::swap($factory);
(new StellarUserServiceProvider($app))->register();
$checks = 0;
function verify(bool $condition, string $name): void {
    global $checks;
    if (!$condition) throw new RuntimeException('Runtime check failed: '.$name);
    $checks++;
}
$client = $app->make(UserApiClient::class);
verify($client instanceof UserService, 'compatible class');
verify($client === $app->make(UserService::class) && $client === $app->make('stellar.user'), 'container aliases');
verify($client->loginSession('synthetic@example.test', 'synthetic-user-password')->status() === 401, 'typed failure returned without retry exception');
$request = $factory->recorded()[0][0];
verify($request->url() === 'https://identity.example.test/api/v1/sessioncontroller/login', 'new login endpoint');
verify($request->data() === ['username' => 'synthetic@example.test', 'password' => 'synthetic-user-password'], 'server default expiry');
verify($request->hasHeader('Authorization', 'Basic '.base64_encode('synthetic-service:synthetic-password')), 'published config keys');
$expiry = new DateTimeImmutable('2030-01-01T12:00:00+02:00');
$client->registerSession('synthetic@example.test', 'synthetic-user-password', $expiry);
verify($factory->recorded()[1][0]->data()['expires_at'] === $expiry->format(DATE_ATOM), 'explicit expiry retained');
$token = '1|'.str_repeat('a', 40);
$client->introspectSession($token);
StellarUser::logoutSession($token);
foreach ([2 => 'introspect', 3 => 'logout'] as $index => $method) {
    $request = $factory->recorded()[$index][0];
    verify(str_ends_with($request->url(), '/sessioncontroller/'.$method), 'scoped '.$method.' path');
    verify($request->data() === ['token' => $token] && !str_contains($request->url(), $token), 'token not in URL');
}
verify(count($factory->recorded()) === 4, 'one request per operation');
foreach ($optionsSeen as $options) {
    verify($options['allow_redirects'] === false && $options['verify'] === true && $options['timeout'] === 15 && $options['connect_timeout'] === 5, 'safe scoped transport');
}
try { $client->logoutSession('invalid'); throw new RuntimeException('Invalid token accepted'); }
catch (InvalidArgumentException) { verify(count($factory->recorded()) === 4, 'invalid token not transmitted'); }
try { (new UserService('http://identity.example.test/api/'))->loginSession('synthetic@example.test', 'synthetic'); throw new RuntimeException('Insecure URL accepted'); }
catch (InvalidArgumentException) { verify(true, 'HTTPS required for new methods'); }

// Verify legacy config names still win when explicitly provided.
$app['config']->set('stellar-user.username_env', 'STELLAR_PACKAGE_LEGACY_USERNAME');
$app['config']->set('stellar-user.password_env', 'STELLAR_PACKAGE_LEGACY_PASSWORD');
putenv('STELLAR_PACKAGE_LEGACY_USERNAME=legacy-synthetic-user');
putenv('STELLAR_PACKAGE_LEGACY_PASSWORD=legacy-synthetic-password');
(new UserService())->loginSession('synthetic@example.test', 'synthetic');
verify($factory->recorded()[4][0]->hasHeader('Authorization', 'Basic '.base64_encode('legacy-synthetic-user:legacy-synthetic-password')), 'legacy config precedence');
$before = count($factory->recorded());
$nonce = rtrim(strtr(base64_encode(str_repeat('n', 32)), '+/', '-_'), '=');
$client->getIdentityKeys();
$client->getLoginMethod('  SYNTHETIC@example.test ', $nonce);
$client->resolveToken($token);
$requests = $factory->recorded();
verify($requests[$before][0]->method() === 'GET' && str_ends_with($requests[$before][0]->url(), '/v2/auth/keys'), 'public identity keys path');
verify($requests[$before + 1][0]->data() === ['email' => 'synthetic@example.test', 'nonce' => $nonce], 'signed method canonical payload');
verify($requests[$before + 2][0]->data() === ['token' => $token] && !str_contains($requests[$before + 2][0]->url(), $token), 'common token lookup uses POST body');
verify(count($requests) === $before + 3, 'no automatic identity retries');
foreach (array_slice($optionsSeen, $before) as $options) {
    verify($options['allow_redirects'] === false && $options['verify'] === true && $options['timeout'] === 15, 'bounded identity transport');
}
foreach ([['bad-email', $nonce], ['synthetic@example.test', 'invalid'], ['synthetic@example.test', str_repeat('_', 43)]] as [$email, $badNonce]) {
    try { $client->getLoginMethod($email, $badNonce); throw new RuntimeException('Invalid method accepted'); }
    catch (InvalidArgumentException) { verify(count($factory->recorded()) === $before + 3, 'invalid method never transmitted'); }
}
foreach (['', str_repeat('x', 1025)] as $badToken) {
    try { $client->resolveToken($badToken); throw new RuntimeException('Invalid token accepted'); }
    catch (InvalidArgumentException) { verify(count($factory->recorded()) === $before + 3, 'invalid identity token never transmitted'); }
}
echo $checks." runtime checks passed with fake HTTP and synthetic credentials only.\n";
