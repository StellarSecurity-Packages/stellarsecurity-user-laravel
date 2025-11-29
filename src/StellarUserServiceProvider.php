<?php

namespace StellarSecurity\UserApiLaravel;

use Illuminate\Support\ServiceProvider;

/**
 * Register the Stellar User API client into the Laravel container.
 */
class StellarUserServiceProvider extends ServiceProvider
{
    /**
     * Register bindings.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/stellar-user.php', 'stellar-user');

        $this->app->singleton(UserApiClient::class, function ($app) {
            return new UserApiClient();
        });

        // Optional: alias so you can type-hint UserApiClient or 'stellar.user'
        $this->app->alias(UserApiClient::class, 'stellar.user');
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/stellar-user.php' => config_path('stellar-user.php'),
        ], 'config');
    }
}
