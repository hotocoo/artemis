using ACT.SourceAnalysis;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the source-rule false-positive reductions: template-literal rejection in the
/// generic-secret validator and test-file exclusion in the rule engine. These pin the accuracy
/// fixes found by cross-checking Artemis findings against the chatroom repository.
/// </summary>
public class SourceRuleFalsePositiveTests
{
    private static SourceRuleEngine EngineFor(string ruleId) =>
        new([DefaultSourceRules.All.First(r => r.RuleId == ruleId)]);

    // ---------- template literal rejection ----------

    [Fact]
    public async Task GenericSecretRule_RejectsTemplateLiteralInterpolation()
    {
        // token=${encodeURIComponent(tok)} is code that resolves to a value, not a literal secret.
        var line = "const url = `?token=${encodeURIComponent(tok)}`";
        var file = new FileContext("src/app.ts", "/tmp/src/app.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_RejectsEnvVariableReference()
    {
        // SECRET=${MY_LONG_ENV_VARIABLE_NAME} is an environment reference, not a literal secret.
        var line = "const SECRET = ${MY_LONG_ENV_VARIABLE_NAME}";
        var file = new FileContext("src/config.ts", "/tmp/src/config.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_StillDetectsRealHighEntropySecret()
    {
        // A genuine high-entropy literal must still be flagged.
        var line = "const password = Xk9#mQ2vL8@nR5tWz3pYb";
        var file = new FileContext("src/config.ts", "/tmp/src/config.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    // ---------- test file exclusion ----------

    [Theory]
    [InlineData("backend/internal/agent/agent_scope_invariant_test.go")]
    [InlineData("frontend/src/stores/messages.test.ts")]
    [InlineData("frontend/src/stores/messages.spec.ts")]
    [InlineData("tests/test_auth.py")]
    [InlineData("src/ProgramTests.cs")]
    [InlineData("src/__tests__/auth.test.js")]
    [InlineData("src/test_helpers.py")]
    public void IsTestFile_DetectsConventionalTestPaths(string path)
    {
        Assert.True(SourceRuleEngine.IsTestFile(path), "Expected test file: " + path);
    }

    [Theory]
    [InlineData("src/Program.cs")]
    [InlineData("backend/internal/agent/agent.go")]
    [InlineData("src/config.ts")]
    [InlineData("scripts/deploy.sh")]
    public void IsTestFile_IgnoresNonTestPaths(string path)
    {
        Assert.False(SourceRuleEngine.IsTestFile(path), "Expected non-test file: " + path);
    }

    [Fact]
    public async Task GenericSecretRule_SkipsTestFiles()
    {
        // A high-entropy value in a _test.go file must NOT be flagged by the generic rule.
        var line = "const secret = LAUNCH_CODES_XQ7V_PINEAPPLE";
        var file = new FileContext(
            "backend/internal/agent/agent_scope_invariant_test.go",
            "/tmp/backend/internal/agent/agent_scope_invariant_test.go",
            SourceLanguage.Unknown, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_StillScansNonTestFiles()
    {
        // The same value in a non-test file MUST be flagged.
        var line = "const secret = LAUNCH_CODES_XQ7V_PINEAPPLE";
        var file = new FileContext(
            "backend/internal/agent/config.go",
            "/tmp/backend/internal/agent/config.go",
            SourceLanguage.Unknown, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    // ---------- helper ----------

    private static async IAsyncEnumerable<FileLine> StreamLines(params string[] lines)
    {
        for (var i = 0; i < lines.Length; i++)
        {
            yield return new FileLine(i + 1, lines[i]);
            await Task.Yield();
        }
    }
}
