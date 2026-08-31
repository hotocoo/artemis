using ACT.SourceAnalysis;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the lethe-repo accuracy fixes: binary-file exclusion in the walker and
/// code-expression rejection in the generic-secret validator. These pin the gaps found by
/// cross-checking Artemis findings against the lethe browser repository.
/// </summary>
public class LetheAccuracyTests
{
    // ---------- binary file detection ----------

    [Fact]
    public void IsBinaryFile_DetectsNullBytes()
    {
        var path = Path.GetTempFileName();
        try
        {
            // Write a binary-like payload with null bytes.
            File.WriteAllBytes(path, new byte[] { 0x00, 0x01, 0x02, 0x00, 0xFF, 0xFE });
            Assert.True(RepositoryWalker.IsBinaryFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void IsBinaryFile_DetectsControlByteRatio()
    {
        var path = Path.GetTempFileName();
        try
        {
            // No null bytes, but a high ratio of control bytes (binary-ish).
            var bytes = new byte[200];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)(i % 7 == 0 ? 0x01 : 0x41); // sprinkle control bytes
            }
            File.WriteAllBytes(path, bytes);
            Assert.True(RepositoryWalker.IsBinaryFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void IsBinaryFile_IgnoresTextFiles()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "const x = 1;\nint main() { return 0; }\n");
            Assert.False(RepositoryWalker.IsBinaryFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void IsBinaryFile_IgnoresUtf8MultibyteText()
    {
        var path = Path.GetTempFileName();
        try
        {
            // CJK and emoji are valid text; must not be flagged as binary.
            File.WriteAllText(path, "密码 = secret; // 测试 🚀\n");
            Assert.False(RepositoryWalker.IsBinaryFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ---------- code expression rejection in generic-secret rule ----------

    [Fact]
    public async Task GenericSecretRule_RejectsFunctionCallExpression()
    {
        // token = trimCopy(value.substr(pos, ...)) is code, not a literal secret.
        var line = "std::string token = trimCopy(value.substr(pos, semi - pos));";
        var file = new FileContext("src/hsts.cc", "/tmp/src/hsts.cc", SourceLanguage.Cpp, 100);
        var engine = new SourceRuleEngine([DefaultSourceRules.All.First(r => r.RuleId == "SRC-SECRET-002")]);

        var result = await engine.EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_RejectsPropertyAccess()
    {
        // password:pass.stringValue is a property access, not a literal secret.
        var line = "password:pass.stringValue";
        var file = new FileContext("src/win.mm", "/tmp/src/win.mm", SourceLanguage.Unknown, 100);
        var engine = new SourceRuleEngine([DefaultSourceRules.All.First(r => r.RuleId == "SRC-SECRET-002")]);

        var result = await engine.EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_StillDetectsLiteralSecret()
    {
        // A genuine high-entropy literal must still be flagged.
        var line = "const char* password = \"Xk9#mQ2vL8@nR5tWz3pYb\";";
        var file = new FileContext("src/conf.cc", "/tmp/src/conf.cc", SourceLanguage.Cpp, 100);
        var engine = new SourceRuleEngine([DefaultSourceRules.All.First(r => r.RuleId == "SRC-SECRET-002")]);

        var result = await engine.EvaluateAsync(file, StreamLines(line), CancellationToken.None);

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
