<?php

require __DIR__.'/opaque-runtime.php';

$before = count($factory->recorded());
$sent = 0;
$starts = [
    'register' => ['email' => 'new@example.invalid', 'registrationRequest' => 'public-registration-message'],
    'enroll' => ['token' => $token, 'registrationRequest' => 'public-registration-message'],
    'password' => ['token' => $token, 'registrationRequest' => 'public-registration-message', 'authorizationRequest' => 'public-authorization-message'],
    'recovery-setup' => ['token' => $token, 'registrationRequest' => 'public-registration-message', 'authorizationRequest' => 'public-authorization-message'],
    'recover' => ['accountId' => '1', 'email' => 'existing@example.invalid', 'registrationRequest' => 'public-registration-message', 'authorizationRequest' => 'public-authorization-message'],
    'delete' => ['token' => $token, 'authorizationRequest' => 'public-authorization-message'],
];
$proof = base64_encode(str_repeat('p', 32));
foreach ($starts as $flow => $body) {
    $operations = ['start' => $body];
    if ($flow !== 'delete') {
        $operations['prove'] = [
            'challengeId' => $challenge,
            'registrationRecord' => 'public-registration-record',
            'startLoginRequest' => 'public-login-message',
            'keyEnvelope' => base64_encode(str_repeat('e', 60)),
        ];
        if (! in_array($flow, ['register', 'enroll'], true)) {
            $operations['prove']['authorizationFinish'] = 'public-authorization-finish';
            $operations['prove']['authorizationProof'] = $proof;
        }
    }
    $operations['finish'] = $flow === 'delete'
        ? ['challengeId' => $challenge, 'authorizationFinish' => 'public-authorization-finish', 'authorizationProof' => $proof]
        : ['challengeId' => $challenge, 'finishLoginRequest' => 'public-finish-message', 'commitProof' => $proof];
    foreach ($operations as $step => $payload) {
        $method = $step.'OpaqueAccount';
        $response = $client->$method($flow, $payload);
        verify($response->status() === 401, 'account '.$flow.' '.$step.' preserves HTTP failures');
        $request = $factory->recorded()[$before + $sent++][0];
        verify($request->url() === 'https://identity.example.test/api/v2/auth/account/'.$flow.'/'.$step, 'account flow uses its exact endpoint');
        verify($request->data() === $payload, 'account flow forwards exact proof fields');
        verify(! str_contains($request->url(), $token) && ! str_contains($request->url(), $proof), 'account secrets never enter the URL');
    }
}
verify($sent === 17 && count($factory->recorded()) === $before + $sent, '17 protocol operations each issue one request');
$invalid = [
    fn () => $client->startOpaqueAccount('../usercontroller/login', $starts['register']),
    fn () => $client->startOpaqueAccount('register', $starts['register'] + ['password' => 'never-transmit']),
    fn () => $client->startOpaqueAccount('enroll', $starts['enroll'] + ['accountId' => '2']),
    fn () => $client->proveOpaqueAccount('delete', []),
    fn () => $client->finishOpaqueAccount('recover', ['challengeId' => $challenge, 'finishLoginRequest' => 'public-finish-message', 'commitProof' => 'invalid']),
    fn () => $client->proveOpaqueAccount('enroll', ['challengeId' => $challenge, 'registrationRecord' => 'record', 'startLoginRequest' => 'message', 'keyEnvelope' => 'invalid']),
    fn () => $client->startOpaqueAccount('recover', ['accountId' => 'invalid', 'registrationRequest' => 'message', 'authorizationRequest' => 'message']),
];
foreach ($invalid as $operation) {
    try {
        $operation();
        throw new RuntimeException('Invalid account request was accepted.');
    } catch (InvalidArgumentException) {
        verify(count($factory->recorded()) === $before + $sent, 'invalid account fields are rejected before HTTP');
    }
}
foreach (array_slice($optionsSeen, $before) as $options) {
    verify($options['allow_redirects'] === false && $options['verify'] === true
        && $options['timeout'] === 15 && $options['connect_timeout'] === 5, 'account transport remains bounded and verifies TLS');
}
echo $checks." combined SDK account-flow checks passed; fake HTTP only.\n";
