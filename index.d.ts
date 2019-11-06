export declare class GCM {
  /**
   * @param password {string} password string, will use PBKDF2 to drive encryption key.
   * @param options  {object} optional algorithm parameters.
   *          specific this parameter to custom your own encryption algorithm.
   *          {algorithm: <string. Encrypto algorithm, can be aes-1228-gcm, aes-192-gcm or aes-256-gcm>,
   *           saltLength: <integer. key salt length, default 64.>
   *           pbkdf2Rounds: <integer. PBKDF2 rounds, default 10000. Use large value to slow pbkdf2>,
   *           pbkdf2Digest: <string. PBKDF2 digest algorithm, default is sha512>
   */
  constructor(
    password: string,
    options: {
      algorithm?: string;
      saltLength?: number;
      pbkdf2Rounds?: number;
      pbkdf2Digest?: string;
    }
  );

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
  encrypt(plainText: string): string;

  /**
   * decrypt encyptedData.
   *
   * @param encryptedData {string} encrypted data, url safe base64 encoded.
   * @returns {*} decrypted data, utf-8 encoded. or null if decrypt failed.
   */
  decrypt(encryptedData: string): string;
}

// export GCM;
