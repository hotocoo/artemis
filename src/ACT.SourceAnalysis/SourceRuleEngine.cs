using System.Text.RegularExpressions;

namespace ACT.SourceAnalysis;

/// <summary>One rule hit inside a specific numbered line of one file.</summary>
public sealed record SourceRuleMatch(SourceRule Rule, int LineNumber, string LineText, string MatchedText);

/// <summary>Evaluation outcome for one file: collected matches plus rules disabled by match timeouts.</summary>
public sealed record RuleScanResult(IReadOnlyList<SourceRuleMatch> Matches, IReadOnlyList<string> TimedOutRuleIds);

/// <summary>
/// Evaluates declarative source rules against lazily streamed file lines. Per-rule match budgets
/// and a hard per-match regex timeout bound both result volume and evaluation cost (ReDoS defense).
/// </summary>
public sealed class SourceRuleEngine
{
    private readonly IReadOnlyList<SourceRule> _rules;

    /// <summary>Creates an engine over the given rules; defaults to the built-in Artemis rule set.</summary>
    public SourceRuleEngine(IReadOnlyList<SourceRule>? rules = null)
    {
        _rules = rules ?? DefaultSourceRules.All;
    }

    /// <summary>The active rule set.</summary>
    public IReadOnlyList<SourceRule> Rules => _rules;

    /// <summary>Evaluates all rules whose language filter admits the file.</summary>
    public async Task<RuleScanResult> EvaluateAsync(
        FileContext file,
        IAsyncEnumerable<FileLine> lines,
        CancellationToken cancellationToken)
    {
        var isTestFile = IsTestFile(file.RelativePath);
        var applicable = new List<SourceRule>();
        foreach (var rule in _rules)
        {
            if (rule.SkipTestFiles && isTestFile)
            {
                continue;
            }

            if (rule.Languages is null || rule.Languages.Count == 0 || rule.Languages.Contains(file.Language))
            {
                applicable.Add(rule);
            }
        }

        var remaining = new Dictionary<SourceRule, int>(ReferenceEqualityComparer.Instance);
        foreach (var rule in applicable)
        {
            remaining[rule] = rule.MaxMatchesPerFile;
        }

        var matches = new List<SourceRuleMatch>();
        var timedOut = new SortedSet<string>(StringComparer.Ordinal);

        await foreach (var line in lines.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            for (var index = applicable.Count - 1; index >= 0; index--)
            {
                var rule = applicable[index];
                if (remaining[rule] <= 0)
                {
                    continue;
                }

                try
                {
                    var current = rule.Pattern.Match(line.Text);
                    while (current.Success && remaining[rule] > 0)
                    {
                        var captured = current.Groups["secret"] is { Success: true } secretGroup
                            ? secretGroup.Value
                            : current.Value;
                        var admitted = rule.MatchValidator is null
                                       || current.Groups["secret"] is not { Success: true }
                                       || rule.MatchValidator(captured);
                        if (admitted)
                        {
                            matches.Add(new SourceRuleMatch(rule, line.Number, line.Text, captured));
                            remaining[rule]--;
                        }

                        if (current.Length == 0)
                        {
                            break;
                        }

                        current = current.NextMatch();
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    // The ReDoS guard tripped: disable the rule for this file and report honestly.
                    timedOut.Add(rule.RuleId);
                    applicable.RemoveAt(index);
                }
            }
        }

        return new RuleScanResult(matches, timedOut.ToArray());
    }

    /// <summary>
    /// True when a file path matches conventional test-file naming across ecosystems. Generic
    /// secret rules skip these to avoid fixture noise; recognized-format secret rules still run.
    /// </summary>
    public static bool IsTestFile(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)) return false;

        var fileName = Path.GetFileName(relativePath);
        var lower = fileName.ToLowerInvariant();

        // Suffix-based: *_test.go, *_test.py, *Test.cs, *Tests.cs, *Test.java, *_test.rs, ...
        if (lower.EndsWith("_test.go") || lower.EndsWith("_test.py") || lower.EndsWith("_test.rs") ||
            lower.EndsWith("_test.java") || lower.EndsWith("_test.cpp") || lower.EndsWith("_test.cc") ||
            lower.EndsWith("_test.c") || lower.EndsWith("test.go") || lower.EndsWith("test.py"))
        {
            return true;
        }

        if (lower.EndsWith("test.cs") || lower.EndsWith("tests.cs") ||
            lower.EndsWith("test.csx") || lower.EndsWith("tests.csx"))
        {
            return true;
        }

        // Kotlin: JUnit's *Test / *Tests, Spek's *Spec.
        if (lower.EndsWith("test.kt") || lower.EndsWith("tests.kt") || lower.EndsWith("spec.kt"))
        {
            return true;
        }

        // Swift: XCTest's *Tests, Quick's *Spec.
        if (lower.EndsWith("tests.swift") || lower.EndsWith("spec.swift"))
        {
            return true;
        }

        // Prefix-based: test_*.py, test_*.go, test_*.js
        if (lower.StartsWith("test_"))
        {
            return true;
        }

        // JS/TS/Jest/Vitest conventions: *.test.*, *.spec.*
        if (lower.Contains(".test.") || lower.Contains(".spec."))
        {
            return true;
        }

        // Directory-based: files under a dedicated tests/test/spec directory.
        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var segments = relativePath.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            var segLower = segment.ToLowerInvariant();
            if (segLower is "test" or "tests" or "spec" or "specs" or "__tests__")
            {
                return true;
            }
        }

        return false;
    }
}

