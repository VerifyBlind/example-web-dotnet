using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using VerifyBlind.Server;
using Xunit;

namespace VerifyBlind.TestPortal.Tests;

/// <summary>
/// A local stand-in for the VerifyBlind API (public keys + pop/generate), plus the portal under test.
/// The portal reads its settings from environment variables, so they are set before it starts.
/// </summary>
public sealed class PortalFixture : IAsyncLifetime
{
    public RSA WebhookSigner { get; } = RSA.Create(2048);   // VerifyBlind webhook-signing key
    public RSA Enclave { get; } = RSA.Create(2048);         // enclave result-signing key
    public VerifyBlindCallbackKey CallbackKey { get; } = VerifyBlindCallbackKey.Generate(); // the partner's fixed key
    public ConcurrentQueue<string> GenerateBodies { get; } = new();

    private WebApplication? _stub;
    public WebApplicationFactory<Program> Factory { get; private set; } = null!;
    public HttpClient Client { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        _stub = builder.Build();
        _stub.MapGet("/api/public/webhook-signing-key", () => Results.Json(new
        {
            public_key = new string(PemEncoding.Write("PUBLIC KEY", WebhookSigner.ExportSubjectPublicKeyInfo()))
        }));
        _stub.MapGet("/api/public/enclave-key", () => Convert.ToBase64String(Enclave.ExportSubjectPublicKeyInfo()));
        _stub.MapPost("/api/pop/generate", async (HttpRequest req) =>
        {
            GenerateBodies.Enqueue(await new StreamReader(req.Body).ReadToEndAsync());
            return Results.Json(new { nonce = "n-" + Guid.NewGuid().ToString("N") });
        });
        await _stub.StartAsync();
        var stubUrl = _stub.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First();

        Environment.SetEnvironmentVariable("VERIFYBLIND_API_URL", stubUrl);
        Environment.SetEnvironmentVariable("TEST_VERIFYBLIND_API_KEY", "test-api-key");
        Environment.SetEnvironmentVariable("CALLBACK_URL", "https://test.verifyblind.com/net/api/callback");
        Environment.SetEnvironmentVariable("CALLBACK_PRIVATE_KEY", CallbackKey.ExportPkcs8Base64());

        Factory = new WebApplicationFactory<Program>();
        Client = Factory.CreateClient();
    }

    public async Task DisposeAsync()
    {
        Client.Dispose();
        await Factory.DisposeAsync();
        if (_stub is not null) await _stub.DisposeAsync();
    }

    /// <summary>Signs a webhook body like VerifyBlind: RSA-PSS-SHA256 over "{timestamp}.{rawBody}".</summary>
    public HttpRequestMessage SignedWebhook(string path, string rawBody, long? timestamp = null, RSA? signer = null)
    {
        var ts = (timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
        var sig = (signer ?? WebhookSigner).SignData(Encoding.UTF8.GetBytes($"{ts}.{rawBody}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var msg = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(rawBody, Encoding.UTF8, "application/json"),
        };
        msg.Headers.Add("X-Webhook-Timestamp", ts);
        msg.Headers.Add("X-Webhook-Signature", Convert.ToBase64String(sig));
        return msg;
    }

    /// <summary>
    /// What the enclave sends in a pattern B callback: { payload, signature } encrypted with AES-256-GCM,
    /// the AES key base64-encoded and wrapped with the partner public key (RSA-OAEP-SHA256).
    /// </summary>
    public string CallbackBody(string nonce, object validations)
    {
        var payload = JsonSerializer.Serialize(new { nonce, validations });
        var signature = Convert.ToBase64String(Enclave.SignData(Encoding.UTF8.GetBytes(payload),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var inner = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { payload, signature }));

        var aesKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[inner.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(aesKey, 16))
            gcm.Encrypt(iv, inner, cipher, tag);
        var blob = iv.Concat(cipher).Concat(tag).ToArray();

        using var partnerPublic = RSA.Create();
        partnerPublic.ImportSubjectPublicKeyInfo(Convert.FromBase64String(CallbackKey.PublicKeyBase64), out _);
        var encKey = partnerPublic.Encrypt(Encoding.UTF8.GetBytes(Convert.ToBase64String(aesKey)), RSAEncryptionPadding.OaepSHA256);

        return JsonSerializer.Serialize(new
        {
            nonce,
            encrypted_response = new { enc_key = Convert.ToBase64String(encKey), blob = Convert.ToBase64String(blob) },
        });
    }
}

public class EndpointTests(PortalFixture fx) : IClassFixture<PortalFixture>
{
    private static JsonElement Json(string s) => JsonDocument.Parse(s).RootElement.Clone();

    private async Task<string> Generate(object validations)
    {
        var res = await fx.Client.PostAsJsonAsync("/api/generate", new { validations });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = Json(await res.Content.ReadAsStringAsync());
        Assert.Equal(fx.CallbackKey.PkHash, body.GetProperty("pk_hash").GetString());
        return body.GetProperty("nonce").GetString()!;
    }

    private async Task<JsonElement> Status(string nonce) =>
        Json(await fx.Client.GetStringAsync($"/api/status/{nonce}"));

    [Fact]
    public async Task Generate_SendsServerChosenValidationsAndCallbackKey_StatusStartsPending()
    {
        var nonce = await Generate(new { age = "18+", user_id = true });

        var upstream = Json(fx.GenerateBodies.Last());
        Assert.Equal(fx.CallbackKey.PublicKeyBase64, upstream.GetProperty("public_key").GetString());
        Assert.Equal("https://test.verifyblind.com/net/api/callback", upstream.GetProperty("callback_url").GetString());
        Assert.Equal("18+", upstream.GetProperty("validations").GetProperty("age").GetString());
        Assert.True(upstream.GetProperty("validations").GetProperty("user_id").GetBoolean());
        Assert.Equal("pending", (await Status(nonce)).GetProperty("status").GetString());
    }

    [Theory]
    [InlineData("""{ "validations": { "age": "1+" } }""")]   // the attack: a looser condition
    [InlineData("""{ "validations": { "age": 18 } }""")]
    [InlineData("""{ "validations": { "user_id": "true" } }""")]
    [InlineData("""{ "validations": { "something_else": true } }""")]
    [InlineData("""{ "validations": [ "age" ] }""")]
    public async Task Generate_AnythingOutsideTheAllowList_Is400_AndNotForwarded(string browserBody)
    {
        var before = fx.GenerateBodies.Count;
        var res = await fx.Client.PostAsync("/api/generate", new StringContent(browserBody, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Equal(before, fx.GenerateBodies.Count);
    }

    [Fact]
    public async Task Callback_DemoCardResult_IsDecryptedChecked_AndServedByStatus()
    {
        var nonce = await Generate(new { age = "18+", user_id = true });
        var body = fx.CallbackBody(nonce, new { age = true, age_condition = "18+", user_id = "TEST_u1", is_test = true });

        var res = await fx.Client.SendAsync(fx.SignedWebhook("/api/callback", body));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var status = await Status(nonce);
        Assert.Equal("completed", status.GetProperty("status").GetString());
        var data = status.GetProperty("data");
        Assert.Equal(nonce, data.GetProperty("nonce").GetString());
        Assert.True(data.GetProperty("validations").GetProperty("age").GetBoolean());
        Assert.Equal("TEST_u1", data.GetProperty("validations").GetProperty("user_id").GetString());
    }

    [Fact]
    public async Task Callback_AnswerToADifferentAgeCondition_IsAckedButNotStored()
    {
        var nonce = await Generate(new { age = "18+" });
        var body = fx.CallbackBody(nonce, new { age = true, age_condition = "1+", is_test = true });

        var res = await fx.Client.SendAsync(fx.SignedWebhook("/api/callback", body));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("pending", (await Status(nonce)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task Callback_NonceNotIssuedByThisServer_IsNotStored()
    {
        var nonce = "n-never-generated";
        var body = fx.CallbackBody(nonce, new { age = true, age_condition = "18+", is_test = true });

        var res = await fx.Client.SendAsync(fx.SignedWebhook("/api/callback", body));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("pending", (await Status(nonce)).GetProperty("status").GetString());
    }

    [Fact]
    public async Task Callback_Cancelled_IsServedByStatus()
    {
        var nonce = await Generate(new { age = "18+" });
        var body = JsonSerializer.Serialize(new { nonce, status = "cancelled", reason = "user_declined" });

        var res = await fx.Client.SendAsync(fx.SignedWebhook("/api/callback", body));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var status = await Status(nonce);
        Assert.Equal("cancelled", status.GetProperty("status").GetString());
        Assert.Equal("user_declined", status.GetProperty("reason").GetString());
    }

    [Theory]
    [InlineData("/api/callback")]
    [InlineData("/api/revoke")]
    public async Task Webhook_SignedBySomeoneElse_Is401InvalidSignature(string path)
    {
        using var stranger = RSA.Create(2048);
        var res = await fx.Client.SendAsync(fx.SignedWebhook(path, """{"nonce":"n-x"}""", signer: stranger));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Equal("invalid signature", Json(await res.Content.ReadAsStringAsync()).GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("/api/callback")]
    [InlineData("/api/revoke")]
    public async Task Webhook_OldTimestamp_Is401StaleTimestamp(string path)
    {
        var old = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3600;
        var res = await fx.Client.SendAsync(fx.SignedWebhook(path, """{"nonce":"n-x"}""", timestamp: old));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Equal("stale timestamp", Json(await res.Content.ReadAsStringAsync()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Revoke_Signed_IsAcked()
    {
        var res = await fx.Client.SendAsync(fx.SignedWebhook("/api/revoke", """{"nonce":"n-r","partner_id":"p"}"""));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Status_UnknownNonce_IsPending()
        => Assert.Equal("pending", (await Status("n-unknown")).GetProperty("status").GetString());
}
