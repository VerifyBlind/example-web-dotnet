using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VerifyBlind.TestPortal.Services;

/// <summary>
/// Callback (webhook) crypto helpers — all pure/stateless and unit-testable.
/// Wire-format compatible with the enclave (see plan Global Constraints).
/// </summary>
public static class CallbackCrypto
{
    /// <summary>
    /// Decrypts encrypted_response: RSA-OAEP-SHA256 unwraps the AES key (double-base64!),
    /// then AES-256-GCM decrypts the blob. Returns the enclave's signed inner payload:
    /// (payload, signature).
    /// </summary>
    public static (string payload, string signature) DecryptEncryptedResponse(
        RSA partnerPrivate, string encKeyB64, string blobB64)
    {
        // 1. Unwrap the AES key — the OAEP output is NOT the raw key, it's a base64 string.
        var wrapped = Convert.FromBase64String(encKeyB64);
        var aesKeyB64Bytes = partnerPrivate.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
        var aesKey = Convert.FromBase64String(Encoding.UTF8.GetString(aesKeyB64Bytes));

        // 2. blob = IV(12) + ciphertext + tag(16)
        var blob = Convert.FromBase64String(blobB64);
        var iv = blob.AsSpan(0, 12).ToArray();
        var tag = blob.AsSpan(blob.Length - 16, 16).ToArray();
        var cipher = blob.AsSpan(12, blob.Length - 12 - 16).ToArray();
        var plain = new byte[cipher.Length];
        using (var gcm = new AesGcm(aesKey, 16))
            gcm.Decrypt(iv, cipher, tag, plain);

        // 3. { payload, signature }
        using var doc = JsonDocument.Parse(plain);
        return (doc.RootElement.GetProperty("payload").GetString()!,
                doc.RootElement.GetProperty("signature").GetString()!);
    }

    /// <summary>Enclave inner signature: RSA-PSS-SHA256, enclave public key = base64 SPKI.</summary>
    /// <remarks>Malformed key/signature (bad base64, bad key) → false, not an exception.</remarks>
    public static bool VerifyEnclaveSignature(string enclavePubKeyBase64Spki, string payload, string signatureB64)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(enclavePubKeyBase64Spki), out _);
            return rsa.VerifyData(
                Encoding.UTF8.GetBytes(payload),
                Convert.FromBase64String(signatureB64),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Webhook signature: RSA-PSS-SHA256 over "{timestamp}.{rawBody}", VerifyBlind webhook PUBLIC key (SPKI PEM).</summary>
    /// <remarks>Malformed PEM/signature (bad base64, bad key) → false, not an exception.</remarks>
    public static bool VerifyWebhookSignature(string webhookPubPem, string timestamp, string rawBody, string signatureB64)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(webhookPubPem);
            return rsa.VerifyData(
                Encoding.UTF8.GetBytes($"{timestamp}.{rawBody}"),
                Convert.FromBase64String(signatureB64),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
        {
            return false;
        }
    }
}
