node-crypto-gcm
===============

[![Build Status](https://travis-ci.org/mingchen/node-crypto-gcm.svg?branch=master)](https://travis-ci.org/mingchen/node-crypto-gcm)

[![NPM](https://nodei.co/npm/node-crypto-gcm.png?downloads=true)](https://nodei.co/npm/node-crypto-gcm/)


## Introduction

A node crypto wrap for AES [GCM (Galois/Counter Mode)](https://en.wikipedia.org/wiki/Galois/Counter_Mode),
to make it easy to use AES GCM mode.

The default crypto algorithm is `aes-128-gcm`. PBKDF2 digest algorithm is `sha512`, PBKDF2 rounds is 10000.

The output text is URL safe base64 encoding, so it can be safely used in URL without URL encoding.


## Install

    npm install node-crypto-gcm


## Usage

    const GCM = require('node-crypto-gcm').GCM;

    let plainText = 'To be or not to be, that is the question.';
    let gcm = new GCM('password');

    let output = gcm.encrypt(plainText);

    let decryptedText = gcm.decrypt(output);    // decryptedText should equals plainText


The crypto algorithm can be customized in constructor.

    let gcm = new GCM('t86GvATWQV6S', {algorithm: 'aes-256-gcm',
                                       saltLenght: 123,
                                       pbkdf2Rounds: 1000,
                                       pbkdf2Digest: 'sha512'});

Checkout [test/gcm_test.js](test/gcm_test.js) for example usages.


## API

    class GCM {

        /**
         * @param password {string} password string, will use PBKDF2 to drive encryption key.
         * @param options  {object} optional algorithm parameters.
         *          specific this parameter to custom your own encryption algorithm.
         *          {algorithm: <string. Encrypto algorithm, can be aes-1228-gcm, aes-192-gcm or aes-256-gcm>,
         *           saltLength: <integer. key salt length, default 64.>
         *           pbkdf2Rounds: <integer. PBKDF2 rounds, default 10000. Use large value to slow pbkdf2>,
         *           pbkdf2Digest: <string. PBKDF2 digest algorithm, default is sha512>
         */
        constructor(password, options)

        /**
         * Encrypt plainText.
         *
         * The output raw buffer format:
         *
         *   <salt(12bytes)> <iv(64bytes)> <authTag(16bytes)> <encryptedData>
         *
         * it will be url safe base64 encoded as function return value.
         *
         * @param plainText  utf-8 encoded plain text.
         * @returns {string} url safe base64 encoded encrypted text.
         */
        encrypt(plainText)

        /**
         * decrypt encyptedData.
         *
         * @param encryptedData {string} encrypted data, url safe base64 encoded.
         * @returns {*} decrypted data, utf-8 encoded. or null if decrypt failed.
         */
        decrypt(encryptedData)
    }


## License

MIT


## References

* [nodejs crypto API](https://nodejs.org/api/crypto.html)
