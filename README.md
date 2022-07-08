[![CI](https://github.com/silviokennecke/apple-pay-token-decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/silviokennecke/apple-pay-token-decoder/actions/workflows/ci.yml) [![Latest Stable Version](https://poser.pugx.org/silviokennecke/apple-pay-token-decoder/v/stable.svg)](https://packagist.org/packages/silviokennecke/apple-pay-token-decoder) [![Total Downloads](https://poser.pugx.org/silviokennecke/apple-pay-token-decoder/downloads.svg)](https://packagist.org/packages/silviokennecke/apple-pay-token-decoder) [![License](https://poser.pugx.org/silviokennecke/apple-pay-token-decoder/license.svg)](https://packagist.org/packages/silviokennecke/apple-pay-token-decoder)


# Apple Pay Token Decoder

This library is used to decode tokens for Apple Pay.

It takes a payment token data and returns an ApplePayPaymentData object.
ex:
```
class SilvioKennecke\ApplePay\Decoding\ApplePayPaymentData#19 (9) {
  private $version =>
  int(1)
  private $applicationPrimaryAccountNumber =>
  string(16) "20427527000"
  private $applicationExpirationDate =>
  string(6) "190731"
  private $currencyCode =>
  string(3) "643"
  private $transactionAmount =>
  int(100000)
  private $deviceManufacturerIdentifier =>
  string(12) "050103073"
  private $paymentDataType =>
  string(8) "3DSecure"
  private $onlinePaymentCryptogram =>
  string(28) "Am+7lPDbobAGVT7hNAoABA=="
  private $eciIndicator =>
  NULL
}
```


## Install

Run `composer require silviokennecke/apple-pay-token-decoder`

## Usage

See https://github.com/silviokennecke/apple-pay-token-decoder/blob/master/examples/decode_token.php

For more information about how Apple Pay tokens decoding works go to:
https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

## Attribution

This is a fork of [PayU-EMEA/apple-pay](https://github.com/PayU-EMEA/apple-pay).
The original library was created by [PayU](https://github.com/PayU-EMEA).

