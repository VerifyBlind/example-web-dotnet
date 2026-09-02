# VerifyBlind — Web Entegrasyon Örneği (.NET, Callback/Webhook)

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

VerifyBlind'i bir ASP.NET web sitesine **sunucu-tarafı (callback/webhook)** deseniyle nasıl entegre
edeceğinizi gösteren örnek (ASP.NET, Razor Pages + minimal API). `example-web-nextjs` ve `example-web-php`
**tarayıcı-decrypt (PoP)** desenini gösterir; bu .NET örneği ise **sunucu-decrypt (callback)** desenini
gösterir: anahtar çifti partner backend'inde durur, doğrulama sonucu imzalı bir webhook ile sunucuya
gelir ve **hiç tarayıcıya düşmez**.

---

## Türkçe

### Hangi deseni seçmeli?
- **Tarayıcı-decrypt (PoP)** — en hızlı kurulum; sonuç tarayıcıda çözülür (php/nextjs örnekleri).
- **Sunucu-decrypt (callback)** — bu örnek. Sabit bir anahtar çiftini backend'inizde tutarsınız; sonuç
  imzalı webhook ile sunucunuza gelir, orada çözülür. Sonucun tarayıcıya hiç düşmemesini istiyorsanız idealdir.

### Akış (callback modu)
1. **Generate** — Tarayıcı `POST /api/generate` çağırır. Sunucu, VerifyBlind `POST /api/pop/generate`'e
   **kendi public key'ini + `callback_url`'ini** ekleyip `X-API-Key` ile iletir; SDK'ya `{ nonce, pk_hash }`
   döner. API key ve private key tarayıcıya **hiç** gösterilmez. (`Program.cs`)
2. **Doğrulama** — Kullanıcı QR'ı VerifyBlind mobil ile okutur. Enclave sonucu partner public key'iyle
   şifreler ve `callback_url`'e (**`POST /api/callback`**) RSA-PSS **imzalı** bir webhook olarak POST eder.
3. **Callback alıcı** (`POST /api/callback`) — sırasıyla: (a) webhook imzasını VerifyBlind'ın **public
   key**'iyle (`GET /api/public/webhook-signing-key`) RSA-PSS doğrula → (b) `encrypted_response`'u **kendi
   private key**'inle çöz (RSA-OAEP-SHA256 + AES-256-GCM) → (c) enclave iç imzasını doğrula → (d) sonucu
   nonce'a göre sakla. (`Services/CallbackCrypto.cs`, `Services/CallbackKeyProvider.cs`)
4. **Status** (`GET /api/status/{nonce}`) — SDK bu ucu poll eder; `completed`/`cancelled`/`pending` döner.
5. **Revoke** (`POST /api/revoke`) — kullanıcı doğrulamayı geri çekince VerifyBlind buraya imzalı
   `{ nonce, partner_id }` POST eder; örnek imzayı doğrulayıp ack'ler (sakladığınız veriyi burada silersiniz).

### Kripto formatı (özet)
- **Webhook imzası:** `RSA-PSS-SHA256`, VerifyBlind özel anahtarıyla imzalı; partner **public key** ile
  doğrular (asimetrik — API key sızsa bile callback forge edilemez). İmza payload'u: `{timestamp}.{rawBody}`.
- **Sonuç şifreleme:** AES-256-GCM payload + AES anahtarı RSA-OAEP-SHA256 ile sarılı. `enc_key` çözülünce
  elde edilen byte'lar ham anahtar DEĞİL, bir **base64 string**tir (çift-encode). `blob = IV(12) + ciphertext + tag(16)`.

### Çalıştırma
```bash
# .env oluşturun (DotNetEnv ile yüklenir):
#   TEST_VERIFYBLIND_API_KEY=<partner API anahtarınız>
#   VERIFYBLIND_API_URL=https://api.verifyblind.com          # varsayılan
#   CALLBACK_URL=https://<sizin-domain>/net/api/callback      # host, kayıtlı partner domain'iyle eşleşmeli
#   CALLBACK_PRIVATE_KEY=<base64 PKCS#8 DER RSA-2048>         # üretim komutu .env.example'da
dotnet run           # uygulama /net taban yolu altında sunulur
dotnet test Tests/   # CallbackCrypto decrypt round-trip + imza testleri
```

> Sonuç deposu (`InMemoryTtlStore`) tek-instance içindir; üretimde Redis/DB kullanın. `callback_url` ve
> `revoke_url` host'u VerifyBlind'a kayıtlı partner domain'inizle eşleşmeli (SSRF koruması).

🌐 [verifyblind.com](https://verifyblind.com) · 🧩 [Next.js örneği](https://github.com/VerifyBlind/example-web-nextjs) · 🧩 [PHP örneği](https://github.com/VerifyBlind/example-web-php)

---

## English

An example of integrating VerifyBlind into an ASP.NET website using the **server-side (callback/webhook)**
pattern (ASP.NET, Razor Pages + minimal API). `example-web-nextjs` and `example-web-php` show the
**browser-decrypt (PoP)** pattern; this .NET example shows the **server-decrypt (callback)** pattern: the
key pair stays on the partner backend, the verification result arrives via a signed webhook and **never
touches the browser**.

### Which pattern?
- **Browser-decrypt (PoP)** — fastest setup; the result is decrypted in the browser (php/nextjs examples).
- **Server-decrypt (callback)** — this example. You hold a fixed key pair on your backend; the result
  arrives via a signed webhook and is decrypted server-side. Ideal when the result must never reach the browser.

### Flow (callback mode)
1. **Generate** — The browser calls `POST /api/generate`. The server forwards to VerifyBlind
   `POST /api/pop/generate` adding **its own public key + `callback_url`** with `X-API-Key`, and returns
   `{ nonce, pk_hash }` to the SDK. The API key and private key are **never** exposed to the browser. (`Program.cs`)
2. **Verification** — The user scans the QR with VerifyBlind mobile. The enclave encrypts the result with
   the partner public key and POSTs an RSA-PSS **signed** webhook to `callback_url` (**`POST /api/callback`**).
3. **Callback receiver** (`POST /api/callback`) — in order: (a) verify the webhook signature (RSA-PSS) with
   VerifyBlind's **public key** (`GET /api/public/webhook-signing-key`) → (b) decrypt `encrypted_response`
   with **your private key** (RSA-OAEP-SHA256 + AES-256-GCM) → (c) verify the enclave inner signature →
   (d) store the result by nonce. (`Services/CallbackCrypto.cs`, `Services/CallbackKeyProvider.cs`)
4. **Status** (`GET /api/status/{nonce}`) — the SDK polls this; returns `completed`/`cancelled`/`pending`.
5. **Revoke** (`POST /api/revoke`) — when the user revokes, VerifyBlind POSTs a signed `{ nonce, partner_id }`
   here; the example verifies the signature and acks (this is where you delete the stored record).

### Crypto format (summary)
- **Webhook signature:** `RSA-PSS-SHA256`, signed with VerifyBlind's private key; the partner verifies with
  the **public key** (asymmetric — a leaked API key cannot forge callbacks). Signed payload: `{timestamp}.{rawBody}`.
- **Result encryption:** AES-256-GCM payload + AES key wrapped with RSA-OAEP-SHA256. Decrypting `enc_key`
  yields NOT the raw key but a **base64 string** (double-encoded). `blob = IV(12) + ciphertext + tag(16)`.

### Running
```bash
# Create .env (loaded via DotNetEnv):
#   TEST_VERIFYBLIND_API_KEY=<your partner API key>
#   VERIFYBLIND_API_URL=https://api.verifyblind.com          # default
#   CALLBACK_URL=https://<your-domain>/net/api/callback       # host must match your registered partner domain
#   CALLBACK_PRIVATE_KEY=<base64 PKCS#8 DER RSA-2048>          # generation command in .env.example
dotnet run           # the app is served under the /net path base
dotnet test Tests/   # CallbackCrypto decrypt round-trip + signature tests
```

> The result store (`InMemoryTtlStore`) is single-instance only; use Redis/DB in production. The
> `callback_url` and `revoke_url` host must match your registered partner domain (SSRF protection).

🌐 [verifyblind.com](https://verifyblind.com) · 🧩 [Next.js example](https://github.com/VerifyBlind/example-web-nextjs) · 🧩 [PHP example](https://github.com/VerifyBlind/example-web-php)
