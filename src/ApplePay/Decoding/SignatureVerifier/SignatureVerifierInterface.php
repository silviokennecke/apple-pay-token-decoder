<?php

namespace SilvioKennecke\ApplePay\Decoding\SignatureVerifier;

interface SignatureVerifierInterface
{
    public function verify(array $paymentData);
}