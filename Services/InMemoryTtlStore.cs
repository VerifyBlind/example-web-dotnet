using System.Collections.Concurrent;

namespace VerifyBlind.TestPortal.Services;

/// <summary>
/// Redis'in yerini tutan basit in-memory TTL store.
/// Singleton olarak kayıt edilmeli.
/// </summary>
public sealed class InMemoryTtlStore : IDisposable
{
    private readonly ConcurrentDictionary<string, (string Value, long ExpiresAtMs)> _store = new();
    private readonly Timer _cleanup;

    public InMemoryTtlStore()
    {
        // Her 10 saniyede bir süresi dolan kayıtları temizle
        _cleanup = new Timer(_ => Cleanup(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    public void Set(string key, string value, int ttlSeconds)
    {
        long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (ttlSeconds * 1000L);
        _store[key] = (value, expiresAt);
    }

    public string? Get(string key)
    {
        if (!_store.TryGetValue(key, out var entry))
            return null;

        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= entry.ExpiresAtMs)
        {
            _store.TryRemove(key, out _);
            return null;
        }

        return entry.Value;
    }

    /// <summary>
    /// Atomically reads and removes a key (one-time consume). Returns null if the key
    /// is absent or already expired — used for nonce replay protection.
    /// </summary>
    public string? GetAndRemove(string key)
    {
        if (!_store.TryRemove(key, out var entry))
            return null;

        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= entry.ExpiresAtMs)
            return null;

        return entry.Value;
    }

    private void Cleanup()
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        foreach (var key in _store.Keys)
        {
            if (_store.TryGetValue(key, out var entry) && now >= entry.ExpiresAtMs)
                _store.TryRemove(key, out _);
        }
    }

    public void Dispose() => _cleanup.Dispose();
}
