using VerifyBlind.Server;

namespace VerifyBlind.TestPortal.Services;

/// <summary>
/// The partner's FIXED callback keypair (held in env). Produces the public key + pk_hash
/// at generate time; decrypts with the private key at webhook time. No per-nonce key
/// management. Loading and the key math are VerifyBlind.Server's <see cref="VerifyBlindCallbackKey"/>;
/// this class only reads the env var with a clear message when it is missing.
/// </summary>
public sealed class CallbackKeyProvider : IDisposable
{
    public VerifyBlindCallbackKey Key { get; }
    public string PublicKeyBase64 => Key.PublicKeyBase64;   // base64 SPKI (SDK/enclave format, no PEM header)
    public string PkHashHex => Key.PkHash;                   // lowercase hex SHA256(UTF8(PublicKeyBase64))

    public CallbackKeyProvider()
    {
        var b64 = Environment.GetEnvironmentVariable("CALLBACK_PRIVATE_KEY");
        if (string.IsNullOrWhiteSpace(b64))
            throw new InvalidOperationException(
                "CALLBACK_PRIVATE_KEY is not set — the callback example needs a fixed RSA keypair (base64 PKCS#8 DER). See .env.example.");

        Key = VerifyBlindCallbackKey.Load(b64);
    }

    public void Dispose() => Key.Dispose();
}
