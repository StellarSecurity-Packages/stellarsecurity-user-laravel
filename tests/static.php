<?php
declare(strict_types=1);
// Standard-library source inspection only. Never includes or executes package code.
function methods(string $source): array
{
    $tokens = token_get_all($source);
    $methods = [];
    for ($index = 0; $index < count($tokens); $index++) {
        if (!is_array($tokens[$index]) || $tokens[$index][0] !== T_FUNCTION) continue;
        $name = null; $depth = 0; $started = false; $body = '';
        for ($next = $index; $next < count($tokens); $next++) {
            $token = $tokens[$next];
            if (is_array($token)) {
                if ($token[0] === T_STRING && $name === null) $name = $token[1];
                if (!in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $body .= $token[1];
            } else {
                $body .= $token;
                if ($token === '{') { $depth++; $started = true; }
                if ($token === '}') $depth--;
                if ($started && $depth === 0) break;
            }
        }
        if ($name !== null) $methods[$name] = $body;
    }
    return $methods;
}
if (count($argv) !== 2) { fwrite(STDERR, "Supply reviewed 1.0.4 source path.\n"); exit(1); }
$root = dirname(__DIR__);
$old = methods($argv[1] === '-' ? stream_get_contents(STDIN) : file_get_contents($argv[1]));
$newSource = file_get_contents($root.'/src/UserService.php');
$new = methods($newSource);
$checks = 0;
function ensure(bool $valid, string $name): void {
    global $checks;
    if (!$valid) throw new RuntimeException('Static check failed: '.$name);
    $checks++;
}
foreach ($old as $name => $body) {
    if ($name !== '__construct') ensure(($new[$name] ?? null) === $body, 'released method unchanged: '.$name);
}
foreach (['loginSession', 'registerSession', 'introspectSession', 'logoutSession'] as $method) ensure(isset($new[$method]), 'additive '.$method);
ensure(str_contains($new['sessionClient'], "'allow_redirects'=>false"), 'no scoped redirects');
ensure(!str_contains($new['sessionClient'], 'retry('), 'no scoped retries');
ensure(str_contains($new['sessionClient'], "'verify'=>true"), 'TLS verification retained');
ensure(str_contains($new['sessionClient'], 'timeout(15)'), 'bounded timeout');
ensure(str_contains($new['introspectSession'], "['token'=>\$token]"), 'introspection POST body');
ensure(str_contains($new['logoutSession'], "['token'=>\$token]"), 'logout POST body');
ensure(!str_contains($new['introspectSession'], "'.\$token"), 'no scoped token URL');
ensure(str_contains($newSource, "config('stellar-user.username_env')"), 'legacy username config');
ensure(str_contains($newSource, "config('stellar-user.username_env_key'"), 'published username config');
$manifest = json_decode(file_get_contents($root.'/composer.json'), true, 512, JSON_THROW_ON_ERROR);
ensure(!isset($manifest['scripts']), 'no package lifecycle scripts');
ensure($manifest['require'] === ['php' => '>=8.1'], 'dependency set unchanged');
ensure(str_contains(file_get_contents($root.'/src/UserApiClient.php'), 'class UserApiClient extends UserService'), 'provider class exists as compatible subclass');
ensure(str_contains(file_get_contents($root.'/src/StellarUserServiceProvider.php'), 'alias(UserApiClient::class, UserService::class)'), 'both container names supported');
echo $checks." static checks passed; package code was not executed.\n";
