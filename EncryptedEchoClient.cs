using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoClient : EchoClientBase {

    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    // We'll store the server's public key here so we can encrypt keys with RSA.
    private RSA? serverPublicKey;

    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    public override void ProcessServerHello(string message) {
        // Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        try {
            byte[] rawKey = Convert.FromBase64String(message);
            serverPublicKey = RSA.Create();
            serverPublicKey.ImportRSAPublicKey(rawKey, out _);
        } catch {
            throw new CryptographicException("Invalid server key");
        }
    }

    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        byte[] aesKey, iv, ciphertext;
        using (Aes aes = Aes.Create()) {
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            aesKey = aes.Key;
            iv = aes.IV;
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            ciphertext = encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        // Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        byte[] hmacKey = new byte[32]; // 256-bit key for HMAC
        RandomNumberGenerator.Fill(hmacKey);
        byte[] hmac;
        using (var h = new HMACSHA256(hmacKey)) {
            hmac = h.ComputeHash(data);
        }

        // Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        if (serverPublicKey == null) {
            throw new CryptographicException("Server public key not set");
        }
        byte[] encryptedAesKey = serverPublicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        byte[] encryptedHmacKey = serverPublicKey.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);

        // Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Field names from Data.cs:
        //   - AesKeyWrap: RSA-encrypted AES key.
        //   - AESIV: the IV.
        //   - Message: the AES ciphertext.
        //   - HMACKeyWrap: RSA-encrypted HMAC key.
        //   - HMAC: the computed HMAC.
        EncryptedMessage messageObj = new EncryptedMessage(
            encryptedAesKey,
            iv,
            ciphertext,
            encryptedHmacKey,
            hmac
        );
        return JsonSerializer.Serialize(messageObj);
    }

    public override string TransformIncomingMessage(string input) {
        // Step 1: Deserialize the message.
        // The server sends a SignedMessage.
        SignedMessage signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);
        // (If deserialization fails, an exception will be thrown.)

        // Step 2: Check the message's signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        if (serverPublicKey == null) {
            throw new CryptographicException("Server public key not set");
        }
        bool valid = serverPublicKey.VerifyData(
            signedMessage.Message,
            signedMessage.Signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );
        if (!valid) {
            throw new InvalidSignatureException("Invalid signature from server");
        }

        // Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}
