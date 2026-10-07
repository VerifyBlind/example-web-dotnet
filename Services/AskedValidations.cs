using System.Text.Json;

namespace VerifyBlind.TestPortal.Services;

/// <summary>
/// What is asked of VerifyBlind is decided by the SERVER, not the browser.
///
/// The enclave signs <c>validations.age: true|false</c> — the answer to the condition it was
/// asked. The browser body can be edited in DevTools, so a server that forwarded the browser's
/// <c>validations</c> could be asked "1+" instead of "18+" and receive a genuinely signed
/// <c>age: true</c>.
///
/// A real site sets validations from its own server configuration and ignores the browser's.
/// This demo lets the visitor pick, so it accepts the browser's choice ONLY from an allow-list
/// (<see cref="Pick"/>), stores what was asked with the nonce, and reads the signed result against
/// that stored condition (<see cref="Check"/>). Pure/stateless and unit-testable.
/// </summary>
public static class AskedValidations
{
    /// <summary>Age conditions the demo page may ask for.</summary>
    public static readonly IReadOnlySet<string> AllowedAgeConditions = new HashSet<string> { "18+" };

    /// <summary>
    /// Returns the allow-listed validations, or null when the browser asked for anything else
    /// (unknown key, another age condition, a non-true user_id, or a non-object).
    /// </summary>
    public static Dictionary<string, object>? Pick(JsonElement requested)
    {
        var asked = new Dictionary<string, object>();
        if (requested.ValueKind == JsonValueKind.Null) return asked;
        if (requested.ValueKind != JsonValueKind.Object) return null;

        foreach (var prop in requested.EnumerateObject())
        {
            if (prop.Name == "age" && prop.Value.ValueKind == JsonValueKind.String
                && AllowedAgeConditions.Contains(prop.Value.GetString()!))
                asked["age"] = prop.Value.GetString()!;
            else if (prop.Name == "user_id" && prop.Value.ValueKind == JsonValueKind.True)
                asked["user_id"] = true;
            else
                return null;
        }
        return asked;
    }

    /// <summary>
    /// Checks the enclave-signed payload against the validations stored with the nonce at generate.
    /// Returns a reason when the result must be rejected, or null when it matches what was asked.
    ///
    /// Newer enclave releases also sign the asked condition as <c>validations.age_condition</c>;
    /// when present it must equal the stored condition. When absent (older enclave), the stored
    /// condition is what <c>age</c> refers to — safe only because generate set validations itself.
    /// </summary>
    public static string? Check(string askedJson, JsonElement payload, string nonce)
    {
        if (!payload.TryGetProperty("nonce", out var n) || n.GetString() != nonce)
            return "imzalı nonce webhook nonce'u ile eşleşmiyor";

        using var askedDoc = JsonDocument.Parse(askedJson);
        var askedAge = askedDoc.RootElement.TryGetProperty("age", out var a) && a.ValueKind == JsonValueKind.String
            ? a.GetString()
            : null;

        var hasValidations = payload.TryGetProperty("validations", out var v) && v.ValueKind == JsonValueKind.Object;
        var hasAge = hasValidations && v.TryGetProperty("age", out _);

        if (askedAge is null)
            return hasAge ? "yaş sorulmadığı halde yaş sonucu geldi" : null;

        if (hasValidations && v.TryGetProperty("age_condition", out var cond)
            && (cond.ValueKind != JsonValueKind.String || cond.GetString() != askedAge))
            return $"sorulan yaş koşulu eşleşmiyor (beklenen {askedAge})";

        return null;
    }
}
