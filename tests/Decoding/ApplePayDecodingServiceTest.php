<?php

namespace PayU\ApplePay\Decoding;

use Exception;
use PayU\ApplePay\Decoding\Decoder\ApplePayDecoderFactory;
use PayU\ApplePay\Decoding\Decoder\ApplePayEccDecoder;
use PayU\ApplePay\ApplePayValidator;
use PHPUnit_Framework_MockObject_MockObject;

use PHPUnit\Framework\TestCase;

class ApplePayDecodingServiceTest extends TestCase
{
    /** @var PHPUnit_Framework_MockObject_MockObject|ApplePayDecoderFactory */
    private $applePayDecoderFactoryMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|PKCS7SignatureValidator */
    private $PKCS7SignatureValidatorMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|ApplePayEccDecoder */
    private $applePayEccDecoderMock;

    /** @var PHPUnit_Framework_MockObject_MockObject|ApplePayValidator */
    private $applePayValidatorMock;

    /** @var ApplePayDecodingService */
    private $applePayDecodingService;

    protected function setUp(): void
    {
        $this->applePayDecoderFactoryMock = $this->getMockBuilder(ApplePayDecoderFactory::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->applePayEccDecoderMock = $this->getMockBuilder(ApplePayEccDecoder::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->applePayDecoderFactoryMock->method('make')->willReturn($this->applePayEccDecoderMock);

        $this->PKCS7SignatureValidatorMock = $this->getMockBuilder(PKCS7SignatureValidator::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->applePayDecodingService = new ApplePayDecodingService($this->applePayDecoderFactoryMock, $this->PKCS7SignatureValidatorMock);

    }

    public function testExceptionIsThrownIfTokenIsNotValid()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('exception_message');

        $this->PKCS7SignatureValidatorMock->method('validate')->willThrowException(new Exception('exception_message'));

        $this->applePayDecodingService->decode('privateKey', 'merchantAppleId', [
            'version' => 1
        ], 'dummy path', 99999);
    }


    public function testExceptionIsThrownIfTokenCannotBeDecoded()
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('exception_message');

        $this->applePayEccDecoderMock->method('decode')->willThrowException(new Exception('exception_message'));

        $this->applePayDecodingService->decode('privateKey', 'merchantAppleId', [
            'version' => 1
        ], 'dummy path', 99999);
    }

    public function testSuccess()
    {
        $expectedPaymentData = new ApplePayPaymentData('param1', 'param2', 'param3', 'param4', 'param5', 'param6', 'param7', 'param8', 'param9');

        $this->applePayEccDecoderMock->method('decode')->willReturn($expectedPaymentData);

        $actualResult = $this->applePayDecodingService->decode(
            'privateKey',
            'merchantAppleId',
            [
                'version' => 1,
                'dummyPaymentData' => []
            ],
            'dummy path',
            99999
        );

        $this->assertEquals($expectedPaymentData, $actualResult);
    }

}
