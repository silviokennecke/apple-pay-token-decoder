<?php

use SilvioKennecke\ApplePay\ApplePayDecodingServiceFactory;
use SilvioKennecke\ApplePay\ApplePayValidator;
use SilvioKennecke\ApplePay\Exception\DecodingFailedException;
use SilvioKennecke\ApplePay\Exception\InvalidFormatException;

require __DIR__ . '/../vendor/autoload.php';

// private key used to create the CSR 
$privateKey = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEV17KjFHD0W014fRRnbM4Un9gkOEYhJz/A/qWPd9PIloAoGCCqGSM4
9AwEHoUQDQgAESRBiGT+GnbM3r1M4fhYEFUKe6EHA+z6r2ctjtWqeAs9wI48MBo
GKFrwWqY/zbzMNYgaOm+DnUMjF8v8v1nMtag==
-----END EC PRIVATE KEY-----';

// merchant identifier from Apple Pay Merchant Account
$appleId = 'merchant.sandbox.payu';

// payment token data received from Apple Pay
$paymentData = '{"version":"EC_v1","data":"UeSmPQQawN6olhB0LNY1cZZ000mToaFGdkMN6OxU9lAAPa9IWPDN9tISOknANVSdkVXi51y2kCqaimjFFuOWFxLNngiZtHdPHLNuz8tgLLVKnvd6mxc40Iz9sQmg93K4BNHGSxC69BGz5QrcrXP3BE96aWtuty3Kuzz+PCiHvEfhMwnW\/EpERJdQrJrDmzUwydRhKNS9Cu1ohLHeQo0ngKjbFon0Io5133h1jYhDsYBnL4vOeNDMFKKH+Rv6nG+U4dsBG1DNXFitMywWVBfGcPWtgEMUQcIJnVP61TTMhQl6dHe13QaWOdW+YYKBMZuBvyUKH+7WuFWZWAEn8m4+Ase0rglxpX14tiprGagjqxRm7QH4zQK4lrVy5JD2DQ26fAUtlvlGxBJz2TAht0FU","signature":"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwEAAKCAMIID5jCCA4ugAwIBAgIIaGD2mdnMpw8wCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwlQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE2MDYwMzE4MTY0MFoXDTIxMDYwMjE4MTY0MFowYjEoMCYGA1UEAwwfZWNjLXNtcC1icm9rZXItc2lnbl9VQzQtU0FOREJPWDEUMBIGA1UECwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgjD9q8Oc914gLFDZm0US5jfiqQHdbLPgsc1LUmeY+M9OvegaJajCHkwz3c6OKpbC9q+hkwNFxOh6RCbOlRsSlaOCAhEwggINMEUGCCsGAQUFBwEBBDkwNzA1BggrBgEFBQcwAYYpaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZWFpY2EzMDIwHQYDVR0OBBYEFAIkMAua7u1GMZekplopnkJxghxFMAwGA1UdEwEB\/wQCMAAwHwYDVR0jBBgwFoAUI\/JJxE+T5O8n5sT2KGw\/orv9LkswggEdBgNVHSAEggEUMIIBEDCCAQwGCSqGSIb3Y2QFATCB\/jCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA2BggrBgEFBQcCARYqaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlYWljYTMuY3JsMA4GA1UdDwEB\/wQEAwIHgDAPBgkqhkiG92NkBh0EAgUAMAoGCCqGSM49BAMCA0kAMEYCIQDaHGOui+X2T44R6GVpN7m2nEcr6T6sMjOhZ5NuSo1egwIhAL1a+\/hp88DKJ0sv3eT3FxWcs71xmbLKD\/QJ3mWagrJNMIIC7jCCAnWgAwIBAgIISW0vvzqY2pcwCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNTA2MjM0NjMwWhcNMjkwNTA2MjM0NjMwWjB6MS4wLAYDVQQDDCVBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwFxGEGddkhdUaXiWBB3bogKLv3nuuTeCN\/EuT4TNW1WZbNa4i0Jd2DSJOe7oI\/XYXzojLdrtmcL7I6CmE\/1RFo4H3MIH0MEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZXJvb3RjYWczMB0GA1UdDgQWBBQj8knET5Pk7yfmxPYobD+iu\/0uSzAPBgNVHRMBAf8EBTADAQH\/MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ3r6966\/ayySrMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMA4GA1UdDwEB\/wQEAwIBBjAQBgoqhkiG92NkBgIOBAIFADAKBggqhkjOPQQDAgNnADBkAjA6z3KDURaZsYb7NcNWymK\/9Bft2Q91TaKOvvGcgV5Ct4n4mPebWZ+Y1UENj53pwv4CMDIt1UQhsKMFd2xd8zg7kGf9F3wsIW2WT8ZyaYISb1T4en0bmcubCYkhYQaZDwmSHQAAMYIBjTCCAYkCAQEwgYYwejEuMCwGA1UEAwwlQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTAghoYPaZ2cynDzANBglghkgBZQMEAgEFAKCBlTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xODAxMjYxMzU1MThaMCoGCSqGSIb3DQEJNDEdMBswDQYJYIZIAWUDBAIBBQChCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIE3cv23pCPQcC4NYY9JgJPyF\/Xmrxnm+lwHQqfvM6Sb1MAoGCCqGSM49BAMCBEgwRgIhAO2PZavNEzOYVVlfnnd+FK+YFMAY+KFAX0x2zYMS9M3IAiEA5rEdGSq\/ljS\/xvLye9zJtSmtzoDuNAjdaDtbjZ21ozAAAAAAAAA=","header":{"ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8VfEh4f\/PF4eTCblWerBJCgpg1BrhZZbpIroEfw\/7OZkkVyAlneu5SIBZXbrQRTrHOfh16Lue4t0y99brvzGFA==","publicKeyHash":"zZPAYNrLOwPbRsav95FZTIYlKF6dULquEHppV6TRPmc=","transactionId":"07e1cfeea3952ca4fcc87d080cf47feb3c3ab2e8fe7261db26457fb361e9d02e"}}';

// how many seconds should the token be valid since the creation time.
$expirationTime = 315360000; // It should be changed in production to a reasonable value (a couple of minutes)

$rootCertificatePath = __DIR__ . '/AppleRootCA-G3.pem';

$applePayDecodingServiceFactory = new ApplePayDecodingServiceFactory();
$applePayDecodingService = $applePayDecodingServiceFactory->make();
$applePayValidator = new ApplePayValidator();

$paymentData = json_decode($paymentData, true);

try {
    $applePayValidator->validatePaymentDataStructure($paymentData);
    $decodedToken = $applePayDecodingService->decode($privateKey, $appleId, $paymentData, $rootCertificatePath, $expirationTime);
    echo 'Decoded token is: '.PHP_EOL.PHP_EOL;
    var_dump($decodedToken);
} catch(DecodingFailedException $exception) {
    echo 'Decoding failed: '.PHP_EOL.PHP_EOL;
    echo $exception->getMessage();
} catch(InvalidFormatException $exception) {
    echo 'Invalid format: '.PHP_EOL.PHP_EOL;
    echo $exception->getMessage();
}

