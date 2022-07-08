<?php

namespace SilvioKennecke\ApplePay\Decoding\Decoder;

use SilvioKennecke\ApplePay\Decoding\Decoder\Algorithms\Ecc;
use SilvioKennecke\ApplePay\Decoding\OpenSSL\OpenSslService;
use SilvioKennecke\ApplePay\Decoding\TemporaryFile\TemporaryFileService;

class ApplePayDecoderFactory
{

    const ECC = 'EC_v1';
    const RSA = 'rsa';

    public function __construct()
    {
    }

    /**
     * @param $version
     * @return mixed|ApplePayEccDecoder
     * @throws \RuntimeException
     */
    public function make($version)
    {
        switch ($version) {
            case self::ECC:
                $temporaryFileService = new TemporaryFileService();
                $openSslService = new OpenSslService();
                $ecc = new Ecc($temporaryFileService, $openSslService);
                return new ApplePayEccDecoder($ecc);
            case self::RSA:
                throw new \RuntimeException('Unsupported type ' . $version);
            default:
                throw new \RuntimeException('Unknown type ' . $version);
        }
    }
}