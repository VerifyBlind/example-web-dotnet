using System.Text.Json;
using VerifyBlind.TestPortal.Services;
using Xunit;

public class AskedValidationsTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void Pick_AllowListedChoice_IsAccepted()
    {
        var asked = AskedValidations.Pick(Json("""{ "age": "18+", "user_id": true }"""));
        Assert.NotNull(asked);
        Assert.Equal("18+", asked!["age"]);
        Assert.Equal(true, asked["user_id"]);
    }

    [Theory]
    [InlineData("""{ "age": "1+" }""")]          // the attack: a looser condition
    [InlineData("""{ "age": 18 }""")]
    [InlineData("""{ "user_id": "true" }""")]
    [InlineData("""{ "something_else": true }""")]
    [InlineData("""[ "age" ]""")]
    public void Pick_AnythingElse_IsRejected(string requested)
        => Assert.Null(AskedValidations.Pick(Json(requested)));

    [Fact]
    public void Check_MatchingAgeCondition_Passes()
        => Assert.Null(AskedValidations.Check("""{"age":"18+"}""",
            Json("""{ "nonce": "n1", "validations": { "age": true, "age_condition": "18+" } }"""), "n1"));

    [Fact]
    public void Check_OlderEnclaveWithoutAgeCondition_Passes()
        => Assert.Null(AskedValidations.Check("""{"age":"18+"}""",
            Json("""{ "nonce": "n1", "validations": { "age": true } }"""), "n1"));

    [Fact]
    public void Check_DifferentAgeCondition_IsRejected()
        => Assert.NotNull(AskedValidations.Check("""{"age":"18+"}""",
            Json("""{ "nonce": "n1", "validations": { "age": true, "age_condition": "1+" } }"""), "n1"));

    [Fact]
    public void Check_AgeResultWithoutAgeAsked_IsRejected()
        => Assert.NotNull(AskedValidations.Check("""{"user_id":true}""",
            Json("""{ "nonce": "n1", "validations": { "age": true, "age_condition": "1+" } }"""), "n1"));

    [Fact]
    public void Check_NonceMismatch_IsRejected()
        => Assert.NotNull(AskedValidations.Check("""{"age":"18+"}""",
            Json("""{ "nonce": "other", "validations": { "age": true } }"""), "n1"));
}
