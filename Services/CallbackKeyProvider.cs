using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.TestPortal.Services;

/// <summary>
/// The partner's FIXED callback keypair (held in env). Produces the public key + pk_hash
/// at generate time; decrypts with the private key at webhook time. No per-nonce key
/// management.
/// </summary>
public sealed class CallbackKeyProvider : IDisposable
{
    public RSA Rsa { get; }
    public string PublicKeyBase64 { get; }   // base64 SPKI (SDK/enclave format, no PEM header)
    public string PkHashHex { get; }         // lowercase hex SHA256(UTF8(PublicKeyBase64))

    public CallbackKeyProvider()
    {
        var b64 = Environment.GetEnvironmentVariable("CALLBACK_PRIVATE_KEY");
        if (string.IsNullOrWhiteSpace(b64))
            throw new InvalidOperationException(
                "CALLBACK_PRIVATE_KEY is not set — the callback example needs a fixed RSA keypair (base64 PKCS#8 DER). See .env.example.");

        Rsa = RSA.Create();
        Rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(b64), out _);

        PublicKeyBase64 = Convert.ToBase64String(Rsa.ExportSubjectPublicKeyInfo());
        PkHashHex = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(PublicKeyBase64))).ToLowerInvariant();
    }

    public void Dispose() => Rsa.Dispose();
}
