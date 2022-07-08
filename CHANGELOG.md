# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2022-07-09

### Changed

- change `\SilvioKennecke\ApplePay\Decoding\SignatureVerifier\EccSignatureVerifier::verify` to take `applicationData` property into count

## [1.2.0] - 2022-07-08

### Changed

- update `phpunit/phpunit` to `^9.5`
- update required php version to `>=7.4`
- change namespace from `\PayU` to `\SilvioKennecke` to differ from the original project
- change `\SilvioKennecke\ApplePay\Decoding\OpenSSL\OpenSslServiceTest` to use current a not outdated leaf certificate
- change `\SilvioKennecke\ApplePay\Decoding\Decoder\Algorithms\Ecc::formatKey` to support already formatted keys