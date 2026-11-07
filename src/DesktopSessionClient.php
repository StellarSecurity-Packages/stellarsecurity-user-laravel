<?php
declare(strict_types=1);
namespace StellarSecurity\UserApiLaravel;
use Illuminate\Http\Client\Response;

/** @deprecated Use DeviceSessionClient from any application backend. Compatibility aliases only. */
class DesktopSessionClient extends DeviceSessionClient
{
    public function renewDesktopSession(#[\SensitiveParameter] string $renewal): Response { return $this->renewDeviceSession($renewal); }
    public function logoutDesktopSession(#[\SensitiveParameter] string $renewal): Response { return $this->revokeDeviceSession($renewal); }
    public function inspectDesktopSession(#[\SensitiveParameter] string $token): Response { return $this->inspectDeviceSession($token); }
}
