using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoServer : EchoServerBase {

    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    // Step 1: Generate a RSA key (2048 bits) for the server.
    private readonly RSA serverRsa;



    internal EncryptedEchoServer(ushort port) : base(port) {
        // Generate the server's 2048-bit RSA key.
        serverRsa = RSA.Create(2048);
    }
 

    public override string GetServerHello() {
        // Step 1: Send the public key to the client in PKCS#1 format.
        // Encode using Base64.
        byte[] publicKey = serverRsa.ExportRSAPublicKey();
        return Convert.ToBase64String(publicKey);
    }

    public override string TransformIncomingMessage(string input) {
        // Step 1: Deserialize the message.
        // The client sends an EncryptedMessage.
        EncryptedMessage message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        // (If deserialization fails, an exception is thrown.)

        // Step 2: Decrypt the message using hybrid encryption.
        // Decrypt the wrapped AES key and HMAC key using RSA (OAEP with SHA256).
        byte[] aesKey = serverRsa.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
        byte[] hmacKey = serverRsa.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);

        // Decrypt the ciphertext using AES in CBC mode with PKCS7 padding.
        byte[] plaintext;
        using (Aes aes = Aes.Create()) {
            aes.Key = aesKey;
            aes.IV = message.AESIV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using ICryptoTransform decryptor = aes.CreateDecryptor();
            plaintext = decryptor.TransformFinalBlock(message.Message, 0, message.Message.Length);
        }

        // Step 3: Verify the HMAC.
        // Compute the HMAC over the plaintext using the decrypted HMAC key.
        using (var hmac = new HMACSHA256(hmacKey)) {
            byte[] computedHmac = hmac.ComputeHash(plaintext);
            if (!CryptographicOperations.FixedTimeEquals(computedHmac, message.HMAC)) {
                throw new InvalidSignatureException("HMAC verification failed");
            }
        }

        // Step 3: Return the decrypted and verified message from the server.
        return Settings.Encoding.GetString(plaintext);
    }

    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // Step 1: Sign the message.
        // Use RSA-PSS padding with SHA256.
        byte[] signature = serverRsa.SignData(
            data,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );

        // Step 2: Put the data in a SignedMessage object and serialize to JSON.
        SignedMessage messageObj = new SignedMessage(data, signature);
        return JsonSerializer.Serialize(messageObj);
    }
}
