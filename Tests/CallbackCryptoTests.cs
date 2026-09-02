using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VerifyBlind.TestPortal.Services;
using Xunit;

public class CallbackCryptoTests
{
    // Mimics what the enclave does: encrypt with AES-GCM, then wrap the AES key
    // (base64-encoded!) with the partner public key via RSA-OAEP-SHA256.
    // Same wire format as the plan's Global Constraints.
    private static (string encKey, string blob) EncryptLikeEnclave(RSA partnerPublic, string innerJson)
    {
        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes(innerJson);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(aesKey, 16))
            gcm.Encrypt(iv, plaintext, cipher, tag);

        var blob = new byte[iv.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(iv, 0, blob, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, blob, iv.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, blob, iv.Length + cipher.Length, tag.Length);

        // AES key is DOUBLE-encoded: the base64 string is OAEP-wrapped as UTF8 bytes.
        var aesKeyB64 = Convert.ToBase64String(aesKey);
        var encKey = partnerPublic.Encrypt(Encoding.UTF8.GetBytes(aesKeyB64), RSAEncryptionPadding.OaepSHA256);
        return (Convert.ToBase64String(encKey), Convert.ToBase64String(blob));
    }

    [Fact]
    public void DecryptEncryptedResponse_RoundTrips()
    {
        using var partner = RSA.Create(2048);
        var inner = JsonSerializer.Serialize(new { payload = "{\"nonce\":\"n-123\"}", signature = "sig-abc" });
        var (encKey, blob) = EncryptLikeEnclave(partner, inner);

        var (payload, signature) = CallbackCrypto.DecryptEncryptedResponse(partner, encKey, blob);

        Assert.Equal("{\"nonce\":\"n-123\"}", payload);
        Assert.Equal("sig-abc", signature);
    }

    [Fact]
    public void VerifyWebhookSignature_ValidSignature_ReturnsTrue()
    {
        using var vb = RSA.Create(2048);
        var pem = new string(PemEncoding.Write("PUBLIC KEY", vb.ExportSubjectPublicKeyInfo()));
        var ts = "1720000000";
        var body = "{\"nonce\":\"n\"}";
        var sig = Convert.ToBase64String(vb.SignData(
            Encoding.UTF8.GetBytes($"{ts}.{body}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        Assert.True(CallbackCrypto.VerifyWebhookSignature(pem, ts, body, sig));
        Assert.False(CallbackCrypto.VerifyWebhookSignature(pem, ts, body + "x", sig)); // tamper
    }

    [Fact]
    public void VerifyEnclaveSignature_ValidSignature_ReturnsTrue()
    {
        using var enclave = RSA.Create(2048);
        var spkiB64 = Convert.ToBase64String(enclave.ExportSubjectPublicKeyInfo());
        var payload = "{\"nonce\":\"n-999\"}";
        var sig = Convert.ToBase64String(enclave.SignData(
            Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        Assert.True(CallbackCrypto.VerifyEnclaveSignature(spkiB64, payload, sig));
        Assert.False(CallbackCrypto.VerifyEnclaveSignature(spkiB64, payload + "x", sig)); // tamper
    }

    [Fact]
    public void VerifySignatures_MalformedInputs_ReturnFalse_NotThrow()
    {
        using var vb = RSA.Create(2048);
        var pem = new string(PemEncoding.Write("PUBLIC KEY", vb.ExportSubjectPublicKeyInfo()));
        var spkiB64 = Convert.ToBase64String(vb.ExportSubjectPublicKeyInfo());

        // Non-base64 signature → false (not FormatException → keeps the webhook endpoint at 401, not 500)
        Assert.False(CallbackCrypto.VerifyWebhookSignature(pem, "123", "body", "not-base64!!"));
        Assert.False(CallbackCrypto.VerifyEnclaveSignature(spkiB64, "payload", "not-base64!!"));
        // Malformed key material → false
        Assert.False(CallbackCrypto.VerifyWebhookSignature("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----", "123", "b", "AAAA"));
        Assert.False(CallbackCrypto.VerifyEnclaveSignature("not-base64!!", "payload", "AAAA"));
    }
}
