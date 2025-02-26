<?php

namespace SilvioKennecke\ApplePay\Decoding\SignatureVerifier;

use SilvioKennecke\ApplePay\Decoding\Asn1Wrapper;
use SilvioKennecke\ApplePay\Decoding\OpenSSL\OpenSslService;
use SilvioKennecke\ApplePay\Decoding\SignatureVerifier\Exception\SignatureException;
use PHPUnit_Framework_MockObject_MockObject;

use PHPUnit\Framework\TestCase;

class EccSignatureVerifierTest extends TestCase
{
    /** @var PHPUnit_Framework_MockObject_MockObject|Asn1Wrapper */
    private $asn1WrapperMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|OpenSslService */
    private $openSslServiceMock;

    /** @var EccSignatureVerifier */
    private $eccSignatureVerifier;

    protected function setUp(): void
    {
        $this->asn1WrapperMock = $this->getMockBuilder(Asn1Wrapper::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->openSslServiceMock = $this->getMockBuilder(OpenSslService::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->asn1WrapperMock->method('loadFromString')->willReturn(true);
        $this->asn1WrapperMock->method('getDigestMessage')->willReturn(hash('sha256', 'dummy_valuedummy_valuedummy_value', true));
        $this->asn1WrapperMock->method('getLeafCertificatePublicKey')->willReturn('dummyValue');

        $this->eccSignatureVerifier = new EccSignatureVerifier($this->asn1WrapperMock, $this->openSslServiceMock);
    }

    public function testOK() {
        $this->openSslServiceMock->method('verifySignature')->willReturn(true);

        $response = $this->eccSignatureVerifier->verify([
            'signature' => 'ZHVtbXlkYXRh',
            'header' => [
                'ephemeralPublicKey' => base64_encode('dummy_value'),
                'transactionId' => bin2hex('dummy_value')
            ],
            'data' => base64_encode('dummy_value')
        ]);

        $this->assertTrue($response);
    }

    public function testInvalidDigest() {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Invalid digest');

        $this->eccSignatureVerifier->verify([
            'signature' => 'ZHVtbXlkYXRh',
            'header' => [
                'ephemeralPublicKey' => base64_encode('invalid_dummy_value'), // change ephemeralPublicKey so it returns a different message digest
                'transactionId' => bin2hex('dummy_value')
            ],
            'data' => base64_encode('dummy_value')
        ]);
    }


    public function testCannotVerifySignature() {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('exception message');

        $this->openSslServiceMock->method('verifySignature')->willThrowException(new SignatureException('exception message'));

        $this->eccSignatureVerifier->verify([
            'signature' => 'ZHVtbXlkYXRh',
            'header' => [
                'ephemeralPublicKey' => base64_encode('dummy_value'), // change ephemeralPublicKey so it returns a different message digest
                'transactionId' => bin2hex('dummy_value')
            ],
            'data' => base64_encode('dummy_value')
        ]);
    }
}
