<?php

require __DIR__.'/runtime.php';

$before = count($factory->recorded());
$challenge = str_repeat('a', 64);
$proof = 'synthetic-client-protocol-message';
$token = '1|'.str_repeat('b', 40);
$operations = [
    ['start', ['email' => 'opaque@example.invalid', 'startLoginRequest' => $proof]],
    ['finish', ['challengeId' => $challenge, 'finishLoginRequest' => $proof]],
    ['session', ['token' => $token]],
    ['logout', ['token' => $token]],
];

verify($client->startOpaqueLogin('opaque@example.invalid', $proof)->status() === 401, 'OPAQUE start preserves failure responses');
verify($client->finishOpaqueLogin($challenge, $proof)->status() === 401, 'OPAQUE finish preserves failure responses');
verify($client->inspectOpaqueSession($token)->status() === 401, 'OPAQUE introspection preserves failure responses');
verify(StellarSecurity\UserApiLaravel\Facades\StellarUser::logoutOpaqueSession($token)->status() === 401, 'OPAQUE facade logout preserves failure responses');

foreach ($operations as $index => [$operation, $body]) {
    $request = $factory->recorded()[$before + $index][0];
    verify($request->url() === 'https://identity.example.test/api/v2/auth/'.$operation, 'OPAQUE '.$operation.' URL');
    verify($request->data() === $body, 'OPAQUE '.$operation.' exact protocol body');
    verify(! str_contains($request->url(), $token) && ! str_contains($request->url(), $proof), 'OPAQUE secrets stay out of URLs');
    verify(! array_key_exists('password', $request->data()), 'OPAQUE method never sends a raw-password field');
    verify($request->hasHeader('Authorization', 'Basic '.base64_encode('synthetic-service:synthetic-password')), 'OPAQUE keeps service authentication');
}
verify(count($factory->recorded()) === $before + 4, 'OPAQUE operations never retry authentication requests');
foreach (array_slice($optionsSeen, $before) as $options) {
    verify($options['allow_redirects'] === false && $options['verify'] === true
        && $options['timeout'] === 15 && $options['connect_timeout'] === 5, 'OPAQUE retains bounded HTTPS transport');
}

$invalid = [
    fn () => $client->startOpaqueLogin('invalid', $proof),
    fn () => $client->startOpaqueLogin('opaque@example.invalid', ''),
    fn () => $client->startOpaqueLogin('opaque@example.invalid', str_repeat('x', 16385)),
    fn () => $client->finishOpaqueLogin('invalid', $proof),
    fn () => $client->finishOpaqueLogin($challenge, ''),
    fn () => $client->inspectOpaqueSession('invalid'),
    fn () => $client->logoutOpaqueSession('invalid'),
    fn () => (new StellarSecurity\UserApiLaravel\UserService('http://identity.example.invalid/api/'))->startOpaqueLogin('opaque@example.invalid', $proof),
];
foreach ($invalid as $operation) {
    try {
        $operation();
        throw new RuntimeException('Invalid OPAQUE input accepted.');
    } catch (InvalidArgumentException) {
        verify(count($factory->recorded()) === $before + 4, 'Invalid OPAQUE input never reaches the network');
    }
}

echo $checks." combined SDK/OPAQUE runtime checks passed; fake HTTP only.\n";
