'use strict';

const crypto = require('crypto');

class GCM {

    /**
     * @param password {string} password string, will use PBKDF2 to drive encryption key.
     * @param options  {object} optional algorithm parameters.
     *          specific this parameter to custom your own encryption algorithm.
 *              {algorithm: <string. Encrypto algorithm, can be aes-1228-gcm, aes-192-gcm or aes-256-gcm>,
     *           saltLength: <integer. key salt length, default 64.>
     *           pbkdf2Rounds: <integer. PBKDF2 rounds, default 10000. Use large value to slow pbkdf2>,
     *           pbkdf2Digest: <string. PBKDF2 digest algorithm, default is sha512>
     */
    constructor(password, options) {
        this.password = password;

        // use `openssl list-cipher-algorithms` to get available cipher algorithms.
        this.algorithm = options && options.algorithm ? options.algorithm : 'aes-128-gcm';
        this.saltLength = options && options.saltLength ? options.saltLength : 64;
        this.ivLength = 12;     // Fixed length, otherwise got "Error: Invalid IV length"
        this.pbkdf2Rounds = options && options.pbkdf2Rounds ? options.pbkdf2Rounds : 10000;
        if (this.algorithm == 'aes-128-gcm') {
            this.pbkdf2KeyLength = 16;  // 128/8 Fixed length, otherwise got "Error: Invalid key length"
        } else if (this.algorithm == 'aes-192-gcm') {
            this.pbkdf2KeyLength = 24;  // 192/8 Fixed length, otherwise got "Error: Invalid key length"
        } else if (this.algorithm == 'aes-256-gcm') {
            this.pbkdf2KeyLength = 32;  // 256/8 Fixed length, otherwise got "Error: Invalid key length"
        } else {
            throw new Error('Invalid algorithm, only aes-128-gcm aes-192-gcm and aes-256-gcm are supported');
        }

        this.pbkdf2Digest = options && options.pbkdf2Digest ? options.pbkdf2Digest : 'sha512';
    }

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
     * @returns {*} url safe base64 encoded encrypted text.
     */
    encrypt(plainText) {

        try {
            // Generates cryptographically strong pseudo-random data. The size argument is a number indicating the number of bytes to generate.
            let iv = crypto.randomBytes(this.ivLength);
            let salt = crypto.randomBytes(this.saltLength);
            let key = crypto.pbkdf2Sync(this.password, salt, this.pbkdf2Rounds, this.pbkdf2KeyLength, this.pbkdf2Digest);
            let cipher = crypto.createCipheriv(this.algorithm, key, iv);
            let encryptedData = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
            let authTag = cipher.getAuthTag();

            return GCM.urlsafe_escape(Buffer.concat([salt, iv, authTag, encryptedData]).toString('base64'));
        } catch (e) {
            // encrypt failed, e.g. algorithm is not correct.
            // console.log(e);
        }

        return null;
    }

    /**
     * decrypt encyptedData.
     *
     * @param encryptedData {string} encrypted data, url safe base64 encoded.
     * @returns {*} decrypted data, utf-8 encoded. or null if decrypt failed.
     */
    decrypt(encryptedData) {
        var rawData = new Buffer(GCM.urlsafe_unescape(encryptedData), 'base64');

        if (rawData.length < 92) {
            return null;
        }

        // convert data to buffers
        let salt = rawData.slice(0, this.saltLength);
        let iv = rawData.slice(this.saltLength, this.saltLength + this.ivLength);
        let authTag = rawData.slice(this.saltLength + this.ivLength, this.saltLength + this.ivLength + 16);
        let data = rawData.slice(this.saltLength + this.ivLength + 16);

        try {
            let key = crypto.pbkdf2Sync(this.password, salt, this.pbkdf2Rounds, this.pbkdf2KeyLength, this.pbkdf2Digest);
            let decipher = crypto.createDecipheriv(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);

            var plainText = decipher.update(data, 'binary', 'utf8');
            plainText += decipher.final('utf8');

            return plainText;
        } catch (e) {
            // failed to decrypt.
            // throw Error: Unsupported state or unable to authenticate data
        }

        return null;
    }

    static urlsafe_escape(data) {
        // / => _
        // + -> .
        // = => -
        return data.replace(/\//g, '_').replace(/\+/g, '.').replace(/=/g, '-');
    }

    static urlsafe_unescape(data) {
        return data.replace(/_/g, '/').replace(/\./g, '+').replace(/-/g, '=');
    }
}

module.exports = {
    GCM: GCM
};

