using System.Text;
using VerifyBlind.TestPortal.Services;

DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder(args);

// ── Sentry ──────────────────────────────────────────────────────────────────
// 3 example portal (nextjs/dotnet/php) tek "verifyblind-examples" projesine raporlar;
// example_stack tag'i hangisi olduğunu ayırır. DSN yoksa Sentry no-op kalır.
builder.WebHost.UseSentry(o =>
{
    o.Dsn = Environment.GetEnvironmentVariable("EXAMPLES_SENTRY_DSN") ?? "";
    o.Environment = builder.Environment.EnvironmentName;
    o.TracesSampleRate = 0.1;
    o.SendDefaultPii = false;
    o.SetBeforeSend((Sentry.SentryEvent e) =>
    {
        e.SetTag("example_stack", "dotnet");
        return e;
    });
});
// ──────────────────────────────────────────────────────────────────────────

builder.Services.AddRazorPages();
builder.Services.AddHttpClient();

// Demo nonce store for PoP login replay protection (use Redis or a shared DB in
// production). In-memory only works single-instance.
builder.Services.AddSingleton<InMemoryTtlStore>();

// Fixed partner callback keypair (env-held). Lazy: only constructed when a callback
// endpoint is first hit, so the app still boots if CALLBACK_PRIVATE_KEY is unset.
builder.Services.AddSingleton<CallbackKeyProvider>();

var app = builder.Build();

// ── Sentry açılış ping'i (sağlık kontrolü) ─────────────────────────────────
// Her açılışta tek Info event'i; example_stack=dotnet tag'i BeforeSend ile eklenir.
Sentry.SentrySdk.CaptureMessage("[startup] example-web-dotnet up", Sentry.SentryLevel.Info);

// /net alt yolu altında sunulduğunda doğru URL üretimi için
app.UsePathBase("/net");

// Statik index.html'i / icin default file olarak serve et (widget)
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapRazorPages();

// ─── POST /api/generate (callback modu) ──────────────────────────────────────
// SDK'dan { validations, additional_data? } alir; VerifyBlind pop/generate'e KENDI
// public key'ini + callback_url'ini ekleyerek gonderir; SDK'ya { nonce, pk_hash } doner.
app.MapPost("/api/generate", async (HttpContext ctx, IHttpClientFactory httpClientFactory,
    InMemoryTtlStore store, CallbackKeyProvider keys) =>
{
    var apiKey = Environment.GetEnvironmentVariable("TEST_VERIFYBLIND_API_KEY") ?? "";
    var apiUrl = Environment.GetEnvironmentVariable("VERIFYBLIND_API_URL") ?? "https://api.verifyblind.com";
    var callbackUrl = Environment.GetEnvironmentVariable("CALLBACK_URL") ?? "";

    if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(callbackUrl))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsJsonAsync(new { error = "TEST_VERIFYBLIND_API_KEY / CALLBACK_URL yapılandırılmamış" });
        return;
    }

    var browserBody = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
    object? validations = null, additionalData = null;
    try
    {
        using var d = System.Text.Json.JsonDocument.Parse(string.IsNullOrWhiteSpace(browserBody) ? "{}" : browserBody);
        if (d.RootElement.TryGetProperty("validations", out var v))
            validations = System.Text.Json.JsonSerializer.Deserialize<object>(v.GetRawText());
        if (d.RootElement.TryGetProperty("additional_data", out var a))
            additionalData = System.Text.Json.JsonSerializer.Deserialize<object>(a.GetRawText());
    }
    catch { /* bos/hatali govde → validations null */ }

    var upstream = System.Text.Json.JsonSerializer.Serialize(new
    {
        public_key = keys.PublicKeyBase64,
        callback_url = callbackUrl,
        validations,
        additional_data = additionalData
    });

    var httpClient = httpClientFactory.CreateClient();
    var request = new HttpRequestMessage(HttpMethod.Post, $"{apiUrl}/api/pop/generate");
    request.Headers.Add("X-API-Key", apiKey);
    var acceptLang = ctx.Request.Headers.AcceptLanguage.ToString();
    request.Headers.TryAddWithoutValidation("Accept-Language", string.IsNullOrEmpty(acceptLang) ? "tr" : acceptLang);
    request.Content = new StringContent(upstream, Encoding.UTF8, "application/json");

    var response = await httpClient.SendAsync(request);
    var responseBody = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        ctx.Response.StatusCode = (int)response.StatusCode;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(responseBody);
        return;
    }

    string? nonce = null;
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(responseBody);
        if (doc.RootElement.TryGetProperty("nonce", out var nEl)) nonce = nEl.GetString();
    }
    catch { /* handled below */ }

    if (string.IsNullOrEmpty(nonce))
    {
        ctx.Response.StatusCode = 502;
        await ctx.Response.WriteAsJsonAsync(new { error = "VerifyBlind nonce döndürmedi" });
        return;
    }

    // Webhook gelene kadar 'pending'; QR tarama penceresi ~10 dk.
    store.Set($"cbresult:{nonce}", "{\"status\":\"pending\"}", 600);

    app.Logger.LogInformation("[Generate-callback] nonce={Nonce} pk_hash={PkHash}", nonce, keys.PkHashHex[..8]);
    await ctx.Response.WriteAsJsonAsync(new { nonce, pk_hash = keys.PkHashHex });
});

// ─── POST /api/callback (VerifyBlind webhook alıcısı) ────────────────────────
// Imza dogrula (RSA-PSS, VerifyBlind webhook public key) → decrypt (kendi private key) →
// enclave imzasi dogrula → sonucu nonce'a gore sakla. statusUrl bunu poll eder.
app.MapPost("/api/callback", async (HttpContext ctx, IHttpClientFactory httpClientFactory,
    InMemoryTtlStore store, CallbackKeyProvider keys) =>
{
    var apiUrl = Environment.GetEnvironmentVariable("VERIFYBLIND_API_URL") ?? "https://api.verifyblind.com";
    var rawBody = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
    var sig = ctx.Request.Headers["X-Webhook-Signature"].ToString();
    var ts  = ctx.Request.Headers["X-Webhook-Timestamp"].ToString();

    // 1. Timestamp tazeligi (replay korumasi, ±300 sn)
    if (!long.TryParse(ts, out var tsSec) ||
        Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - tsSec) > 300)
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "stale timestamp" });
        return;
    }

    // 2. Webhook imzasi — VerifyBlind webhook PUBLIC key ile RSA-PSS dogrula
    var httpClient = httpClientFactory.CreateClient();
    var keyRes = await httpClient.GetAsync($"{apiUrl}/api/public/webhook-signing-key");
    if (!keyRes.IsSuccessStatusCode) { ctx.Response.StatusCode = 502; return; }
    using var keyDoc = System.Text.Json.JsonDocument.Parse(await keyRes.Content.ReadAsStringAsync());
    var webhookPubPem = keyDoc.RootElement.GetProperty("public_key").GetString()!;

    if (string.IsNullOrEmpty(sig) || !CallbackCrypto.VerifyWebhookSignature(webhookPubPem, ts, rawBody, sig))
    {
        app.Logger.LogWarning("[Callback] Geçersiz webhook imzası");
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "invalid signature" });
        return;
    }

    using var body = System.Text.Json.JsonDocument.Parse(rawBody);
    var root = body.RootElement;
    var nonce = root.GetProperty("nonce").GetString()!;

    // 3a. Iptal callback'i
    if (root.TryGetProperty("status", out var stEl) && stEl.GetString() == "cancelled")
    {
        var reason = root.TryGetProperty("reason", out var rEl) ? rEl.GetString() : "user_cancelled";
        store.Set($"cbresult:{nonce}",
            System.Text.Json.JsonSerializer.Serialize(new { status = "cancelled", reason }), 600);
        ctx.Response.StatusCode = 200;
        return;
    }

    // 3b. Basari callback'i — decrypt + enclave-sig dogrula
    try
    {
        var enc = root.GetProperty("encrypted_response");
        var encKey = enc.GetProperty("enc_key").GetString()!;
        var blob = enc.GetProperty("blob").GetString()!;
        var (payload, signature) = CallbackCrypto.DecryptEncryptedResponse(keys.Rsa, encKey, blob);

        var encKeyRes = await httpClient.GetAsync($"{apiUrl}/api/public/enclave-key");
        var enclavePub = (await encKeyRes.Content.ReadAsStringAsync()).Trim();
        if (!CallbackCrypto.VerifyEnclaveSignature(enclavePub, payload, signature))
        {
            app.Logger.LogWarning("[Callback] Geçersiz enclave imzası, nonce={Nonce}", nonce);
            ctx.Response.StatusCode = 200; // webhook'u onayla ama sonucu saklama
            return;
        }

        // payload = enclave imzali ic yuk: { nonce, validations:{...}, additional_data? }
        using var claims = System.Text.Json.JsonDocument.Parse(payload);
        store.Set($"cbresult:{nonce}",
            System.Text.Json.JsonSerializer.Serialize(new { status = "completed", data = claims.RootElement.Clone() }), 600);

        app.Logger.LogInformation("[Callback] ✅ nonce={Nonce} çözüldü + imza doğrulandı", nonce);
        ctx.Response.StatusCode = 200;
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "[Callback] İşleme hatası, nonce={Nonce}", nonce);
        ctx.Response.StatusCode = 200; // 2xx don ki VerifyBlind retry/hata uretmesin; sonuc 'pending' kalir
    }
});

// ─── GET /api/status/{nonce} (SDK statusUrl bunu poll eder) ──────────────────
app.MapGet("/api/status/{nonce}", (string nonce, InMemoryTtlStore store) =>
{
    var stored = store.Get($"cbresult:{nonce}");
    return Results.Content(stored ?? "{\"status\":\"pending\"}", "application/json");
});

// ─── POST /api/revoke (VerifyBlind revoke webhook alıcısı) ───────────────────
// Kullanici mobil app'ten dogrulamayi geri cektiginde VerifyBlind buraya IMZALI bir
// webhook POST eder: { nonce, partner_id } (callback ile AYNI RSA-PSS imzasi).
// Referans deseni: once IMZAYI DOGRULA, sonra bu nonce'a bagli sakladigin veriyi SIL.
app.MapPost("/api/revoke", async (HttpContext ctx, IHttpClientFactory httpClientFactory) =>
{
    var apiUrl = Environment.GetEnvironmentVariable("VERIFYBLIND_API_URL") ?? "https://api.verifyblind.com";
    var rawBody = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
    var sig = ctx.Request.Headers["X-Webhook-Signature"].ToString();
    var ts  = ctx.Request.Headers["X-Webhook-Timestamp"].ToString();

    // 1. Timestamp tazeligi (replay korumasi, ±300 sn)
    if (!long.TryParse(ts, out var tsSec) ||
        Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - tsSec) > 300)
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "stale timestamp" });
        return;
    }

    // 2. Webhook imzasi — VerifyBlind webhook PUBLIC key ile RSA-PSS dogrula (callback ile birebir ayni)
    var httpClient = httpClientFactory.CreateClient();
    var keyRes = await httpClient.GetAsync($"{apiUrl}/api/public/webhook-signing-key");
    if (!keyRes.IsSuccessStatusCode) { ctx.Response.StatusCode = 502; return; }
    using var keyDoc = System.Text.Json.JsonDocument.Parse(await keyRes.Content.ReadAsStringAsync());
    var webhookPubPem = keyDoc.RootElement.GetProperty("public_key").GetString()!;

    if (string.IsNullOrEmpty(sig) || !CallbackCrypto.VerifyWebhookSignature(webhookPubPem, ts, rawBody, sig))
    {
        app.Logger.LogWarning("[Revoke] Geçersiz webhook imzası");
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "invalid signature" });
        return;
    }

    // 3. Parse { nonce, partner_id }
    using var body = System.Text.Json.JsonDocument.Parse(rawBody);
    var nonce = body.RootElement.TryGetProperty("nonce", out var nEl) ? nEl.GetString() : null;

    // TODO partner: burada bu nonce'a bagli sakladigin kullanici verisini SIL (KVKK geri cekme).
    // Bu ornek dogrulama sonucunu kalici saklamadigindan (cbresult:{nonce} 600s sonra ucar)
    // silinecek kalici veri yok — yalniz imzayi dogrulayip 200 ile ack'liyoruz.
    app.Logger.LogInformation("[Revoke] ✅ İmza doğrulandı, revoke ack, nonce={Nonce}", nonce);
    ctx.Response.StatusCode = 200;
});

app.Run();
