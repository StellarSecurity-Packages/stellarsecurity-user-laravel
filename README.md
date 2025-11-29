# Stellar Security – User API Laravel Client

Small Laravel helper package that talks to the **Stellar User API**  
(create users, login, password reset, profile lookups).

## Install

```bash
composer require stellarsecurity/user-laravel
```

Laravel package auto-discovery will register the service provider and facade.

## Configure

Publish the config (optional):

```bash
php artisan vendor:publish --provider="StellarSecurity\UserApiLaravel\StellarUserServiceProvider" --tag=config
```

In your `.env` you must point to the **real secrets** used for basic auth:

```env
# Which env vars actually contain the username/password
STELLAR_USER_USERNAME_KEY=APPSETTING_API_USERNAME_STELLAR_USER_API
STELLAR_USER_PASSWORD_KEY=APPSETTING_API_PASSWORD_STELLAR_USER_API

# These keys must exist and contain the real credentials
APPSETTING_API_USERNAME_STELLAR_USER_API=your-username
APPSETTING_API_PASSWORD_STELLAR_USER_API=your-password

# Optional: override base URL (for staging / local)
STELLAR_USER_BASE_URL=https://stellaruserapiprod.azurewebsites.net/api/
```

## Usage

You can **type-hint** the client:

```php
use StellarSecurity\UserApiLaravel\UserApiClient;

class RegisterController
{
    public function store(UserApiClient $users)
    {
        $response = $users->create([
            'email' => 'user@example.com',
            'password' => 'secret',
        ]);

        if ($response->failed()) {
            // handle error
        }

        return $response->json();
    }
}
```

Or use the **facade**:

```php
use StellarSecurity\UserApiLaravel\Facades\StellarUser;

// Create user
$res = StellarUser::create([
    'email' => 'user@example.com',
    'password' => 'secret',
]);

// Login
$auth = StellarUser::auth([
    'email' => 'user@example.com',
    'password' => 'secret',
]);

// Send reset password link
StellarUser::sendResetPasswordLink('user@example.com', 'CONFIRM-CODE-123');

// Verify reset code + set new password
StellarUser::verifyResetPasswordConfirmationCode(
    'user@example.com',
    'CONFIRM-CODE-123',
    'new-password-here',
);

// Fetch profile by ID
$profile = StellarUser::user('123')->json();
```

## What is Stellar Security?

Stellar Security is building a Swiss-based privacy & security ecosystem:  
hardened phones, VPN, antivirus, secure cloud and developer SDKs.

This package is just a small building block – a clean Laravel wrapper  
around the Stellar User API so your apps can register, authenticate and  
manage Stellar users with a few lines of code.
