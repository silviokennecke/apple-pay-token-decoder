<?php

namespace PayU\ApplePay\Decoding\OpenSSL;

use PayU\ApplePay\ApplePaySettings;
use PayU\ApplePay\Decoding\TemporaryFile\TemporaryFile;

use PHPUnit\Framework\TestCase;

class OpenSslServiceTest extends TestCase
{
    /** @var OpenSslService */
    private $openSslService;

    private $leafCertificate = 'subject=/CN=ecc-smp-broker-sign_UC4-PROD/OU=iOS Systems/O=Apple Inc./C=US
issuer=/CN=Apple Application Integration CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
-----BEGIN CERTIFICATE-----
MIID4zCCA4igAwIBAgIITDBBSVGdVDYwCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwl
QXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwd
QXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu
Yy4xCzAJBgNVBAYTAlVTMB4XDTE5MDUxODAxMzI1N1oXDTI0MDUxNjAxMzI1N1ow
XzElMCMGA1UEAwwcZWNjLXNtcC1icm9rZXItc2lnbl9VQzQtUFJPRDEUMBIGA1UE
CwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVT
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwhV37evWx7Ihj2jdcJChIY3HsL1v
LCg9hGCV2Ur0pUEbg0IO2BHzQH6DMx8cVMP36zIg1rrV1O/0komJPnwPE6OCAhEw
ggINMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUI/JJxE+T5O8n5sT2KGw/orv9
LkswRQYIKwYBBQUHAQEEOTA3MDUGCCsGAQUFBzABhilodHRwOi8vb2NzcC5hcHBs
ZS5jb20vb2NzcDA0LWFwcGxlYWljYTMwMjCCAR0GA1UdIASCARQwggEQMIIBDAYJ
KoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMg
Y2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0
aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25z
IG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHBy
YWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxl
LmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wNAYDVR0fBC0wKzApoCegJYYjaHR0
cDovL2NybC5hcHBsZS5jb20vYXBwbGVhaWNhMy5jcmwwHQYDVR0OBBYEFJRX22/V
dIGGiYl2L35XhQfnm1gkMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkBh0EAgUA
MAoGCCqGSM49BAMCA0kAMEYCIQC+CVcf5x4ec1tV5a+stMcv60RfMBhSIsclEAK2
Hr1vVQIhANGLNQpd1t1usXRgNbEess6Hz6Pmr2y9g4CJDcgs3apj
-----END CERTIFICATE-----';

    // Header formats differ in openssl 1.1.1
    private $leafCertificate_1_1_1 = 'subject=CN = ecc-smp-broker-sign_UC4-PROD, OU = iOS Systems, O = Apple Inc., C = US
issuer=CN = Apple Application Integration CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
-----BEGIN CERTIFICATE-----
MIID4zCCA4igAwIBAgIITDBBSVGdVDYwCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwl
QXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwd
QXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu
Yy4xCzAJBgNVBAYTAlVTMB4XDTE5MDUxODAxMzI1N1oXDTI0MDUxNjAxMzI1N1ow
XzElMCMGA1UEAwwcZWNjLXNtcC1icm9rZXItc2lnbl9VQzQtUFJPRDEUMBIGA1UE
CwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVT
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwhV37evWx7Ihj2jdcJChIY3HsL1v
LCg9hGCV2Ur0pUEbg0IO2BHzQH6DMx8cVMP36zIg1rrV1O/0komJPnwPE6OCAhEw
ggINMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUI/JJxE+T5O8n5sT2KGw/orv9
LkswRQYIKwYBBQUHAQEEOTA3MDUGCCsGAQUFBzABhilodHRwOi8vb2NzcC5hcHBs
ZS5jb20vb2NzcDA0LWFwcGxlYWljYTMwMjCCAR0GA1UdIASCARQwggEQMIIBDAYJ
KoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMg
Y2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0
aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25z
IG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHBy
YWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxl
LmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wNAYDVR0fBC0wKzApoCegJYYjaHR0
cDovL2NybC5hcHBsZS5jb20vYXBwbGVhaWNhMy5jcmwwHQYDVR0OBBYEFJRX22/V
dIGGiYl2L35XhQfnm1gkMA4GA1UdDwEB/wQEAwIHgDAPBgkqhkiG92NkBh0EAgUA
MAoGCCqGSM49BAMCA0kAMEYCIQC+CVcf5x4ec1tV5a+stMcv60RfMBhSIsclEAK2
Hr1vVQIhANGLNQpd1t1usXRgNbEess6Hz6Pmr2y9g4CJDcgs3apj
-----END CERTIFICATE-----';

    private $intermediateCertificate = 'subject=/CN=Apple Application Integration CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
issuer=/CN=Apple Root CA - G3/OU=Apple Certification Authority/O=Apple Inc./C=US
-----BEGIN CERTIFICATE-----
MIIC7jCCAnWgAwIBAgIISW0vvzqY2pcwCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNTA2MjM0NjMwWhcNMjkwNTA2MjM0NjMwWjB6MS4wLAYDVQQDDCVBcHBsZSBB
cHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwFxGEGddkhdUaXiWB
B3bogKLv3nuuTeCN/EuT4TNW1WZbNa4i0Jd2DSJOe7oI/XYXzojLdrtmcL7I6CmE
/1RFo4H3MIH0MEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29j
c3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZXJvb3RjYWczMB0GA1UdDgQWBBQj8knE
T5Pk7yfmxPYobD+iu/0uSzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw
3qFYM4iapIqZ3r6966/ayySrMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwu
YXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjAQBgoq
hkiG92NkBgIOBAIFADAKBggqhkjOPQQDAgNnADBkAjA6z3KDURaZsYb7NcNWymK/
9Bft2Q91TaKOvvGcgV5Ct4n4mPebWZ+Y1UENj53pwv4CMDIt1UQhsKMFd2xd8zg7
kGf9F3wsIW2WT8ZyaYISb1T4en0bmcubCYkhYQaZDwmSHQ==
-----END CERTIFICATE-----';

    // Header formats differ in openssl 1.1.1
    private $intermediateCertificate_1_1_1 = 'subject=CN = Apple Application Integration CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
issuer=CN = Apple Root CA - G3, OU = Apple Certification Authority, O = Apple Inc., C = US
-----BEGIN CERTIFICATE-----
MIIC7jCCAnWgAwIBAgIISW0vvzqY2pcwCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNTA2MjM0NjMwWhcNMjkwNTA2MjM0NjMwWjB6MS4wLAYDVQQDDCVBcHBsZSBB
cHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwFxGEGddkhdUaXiWB
B3bogKLv3nuuTeCN/EuT4TNW1WZbNa4i0Jd2DSJOe7oI/XYXzojLdrtmcL7I6CmE
/1RFo4H3MIH0MEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29j
c3AuYXBwbGUuY29tL29jc3AwNC1hcHBsZXJvb3RjYWczMB0GA1UdDgQWBBQj8knE
T5Pk7yfmxPYobD+iu/0uSzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw
3qFYM4iapIqZ3r6966/ayySrMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwu
YXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMA4GA1UdDwEB/wQEAwIBBjAQBgoq
hkiG92NkBgIOBAIFADAKBggqhkjOPQQDAgNnADBkAjA6z3KDURaZsYb7NcNWymK/
9Bft2Q91TaKOvvGcgV5Ct4n4mPebWZ+Y1UENj53pwv4CMDIt1UQhsKMFd2xd8zg7
kGf9F3wsIW2WT8ZyaYISb1T4en0bmcubCYkhYQaZDwmSHQ==
-----END CERTIFICATE-----';

    private $publicKey = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE2bliUppPzZ514eAP3VchGbxAHWD
9Mg8bYTHqmQCPRVhKhA9ePuZ6wvBOM97fMu9sHo6GFr00mPAhoT+vww+jg==
-----END PUBLIC KEY-----
';

    private $privateKey = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEV17KjFHD0W014fRRnbM4Un9gkOEYhJz/A/qWPd9PIloAoGCCqGSM49
AwEHoUQDQgAESRBiGT+GnbM3r1M4fhYEFUKe6EHA+z6r2ctjtWqeAs9wI48MBoGK
FrwWqY/zbzMNYgaOm+DnUMjF8v8v1nMtag==
-----END EC PRIVATE KEY-----
';

    protected function setUp(): void
    {
        $this->openSslService = new OpenSslService();
    }

    public function testValidateCertificateChainSuccess()
    {
        $intermediateCertificate = new TemporaryFile();
        $intermediateCertificate->write($this->intermediateCertificate);

        $leafCertificate = new TemporaryFile();
        $leafCertificate->write($this->leafCertificate);

        $response = $this->openSslService->validateCertificateChain(__DIR__ . '/../../../examples/AppleRootCA-G3.pem', $intermediateCertificate->getPath(), $leafCertificate->getPath());

        $this->assertTrue($response);
    }

    public function testValidateCertificateChainFail()
    {
        $this->expectException(\Exception::class);

        $intermediateCertificate = new TemporaryFile();
        $intermediateCertificate->write($this->intermediateCertificate);

        $leafCertificate = new TemporaryFile();
        $leafCertificate->write('invalid certificate');

        $this->openSslService->validateCertificateChain(__DIR__ . '/../../../examples/AppleRootCA-G3.pem', $intermediateCertificate->getPath(), $leafCertificate->getPath());
    }

    public function testVerifySignatureSuccess()
    {
        $signedAttributes = base64_decode('MYGVMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTIxMTE2MTAyNVowKgYJKoZIhvcNAQk0MR0wGzANBglghkgBZQMEAgEFAKEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgwsYUbK8j9xu7zed2B5jbOYSNaenOmC5cf1ZV01+DHOY=');
        $signature = base64_decode('MEUCIEZvNK+I5N/EE6yYCHJqijamwaHHhW9pQAlsCSFocosWAiEAmzl1jc20RxbfVtiD1Z7C5u2UtmKCDHO2s5Eab0fnyys=');

        $publicKey = '-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgjD9q8Oc914gLFDZm0US5jfiqQHd
bLPgsc1LUmeY+M9OvegaJajCHkwz3c6OKpbC9q+hkwNFxOh6RCbOlRsSlQ==
-----END PUBLIC KEY-----';

        $response = $this->openSslService->verifySignature($signedAttributes, $signature, $publicKey);

        $this->assertTrue($response);
    }

    public function testVerifySignatureFail()
    {
        $this->expectException(\Exception::class);

        $signedAttributes = 'invalid_value';
        $signature = 'invalid_value';

        $this->openSslService->verifySignature($signedAttributes, $signature, $this->publicKey);
    }

    public function testGetCertificatesFromPkcs7Success()
    {
        $expectedResponse = $this->leafCertificate . PHP_EOL . PHP_EOL . $this->intermediateCertificate;

        if (getenv('OPENSSL_VERSION') === '1.1.1') {
            $expectedResponse = $this->leafCertificate_1_1_1 . PHP_EOL . PHP_EOL . $this->intermediateCertificate_1_1_1;
        }

        $signature = base64_decode('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');

        $certificateFile = new TemporaryFile();
        $certificateFile->write($signature);

        $response = $this->openSslService->getCertificatesFromPkcs7($certificateFile->getPath());

        $this->assertEquals($expectedResponse, $response);
    }

    public function testGetCertificatesFromPkcs7Fail()
    {
        $this->expectException(\Exception::class);

        $certificateFile = new TemporaryFile();
        $certificateFile->write('invalid signature');

        $this->openSslService->getCertificatesFromPkcs7($certificateFile->getPath());
    }

    public function testGetCertificateExtensionsSuccess()
    {
        $response = $this->openSslService->getCertificateExtensions($this->leafCertificate);
        $this->assertNotEmpty($response);

    }

    public function testGetCertificateExtensionsFail()
    {
        $this->expectException(\Exception::class);

        $this->openSslService->getCertificateExtensions('invalid certificate');
    }

    public function testDeriveKeySuccess()
    {
        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($this->privateKey);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($this->publicKey);

        $expectedKey = base64_decode('hkyWug8AlSS7Nr9fR1TcoDWO9NbicLOui7RXNskAYXc=');

        $response = $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());

        $this->assertEquals($expectedKey, $response);
    }

    public function testDeriveKeyFailIfPrivateKeyIsInvalid()
    {
        $this->expectException(\Exception::class);

        $privateKeyData = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($privateKeyData);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($this->publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }

    public function testDeriveKeyFailIfPublicKeyIsInvalid()
    {
        $this->expectException(\Exception::class);

        $publicKey = 'invalid key';

        $privateKeyFile = new TemporaryFile();
        $privateKeyFile->write($this->privateKey);

        $publicKeyFile = new TemporaryFile();
        $publicKeyFile->write($publicKey);

        $this->openSslService->deriveKey($privateKeyFile->getPath(), $publicKeyFile->getPath());
    }
}
