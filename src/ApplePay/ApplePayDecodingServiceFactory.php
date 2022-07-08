<?php

namespace SilvioKennecke\ApplePay;

use SilvioKennecke\ApplePay\Decoding\ApplePayDecodingService;
use SilvioKennecke\ApplePay\Decoding\Asn1Wrapper;
use SilvioKennecke\ApplePay\Decoding\Decoder\ApplePayDecoderFactory;
use SilvioKennecke\ApplePay\Decoding\OpenSSL\OpenSslService;
use SilvioKennecke\ApplePay\Decoding\PKCS7SignatureValidator;
use SilvioKennecke\ApplePay\Decoding\PKCS7SignatureValidatorSettings;
use SilvioKennecke\ApplePay\Decoding\SignatureVerifier\SignatureVerifierFactory;
use SilvioKennecke\ApplePay\Decoding\TemporaryFile\TemporaryFileService;
use phpseclib\File\ASN1;

class ApplePayDecodingServiceFactory
{
    /**
     * @return ApplePayDecodingService
     */
    public function make()
    {
        $decoderFactory = new ApplePayDecoderFactory();
        $signatureVerifierFactory = new SignatureVerifierFactory();
        $asn1 = new ASN1();
        $asn1Wrapper = new Asn1Wrapper($asn1);
        $temporaryFileService = new TemporaryFileService();
        $openSslService = new OpenSslService();
        $pkcs7SignatureValidatorSettings = new PKCS7SignatureValidatorSettings();
        $pkcs7SignatureValidator = new PKCS7SignatureValidator($signatureVerifierFactory, $asn1Wrapper, $temporaryFileService, $openSslService, $pkcs7SignatureValidatorSettings);

        return new ApplePayDecodingService($decoderFactory, $pkcs7SignatureValidator);
    }

}