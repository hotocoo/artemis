using ACT.Contracts;
using ACT.Evidence;
using ACT.Policy;
using ACT.Risk;
using Xunit;

namespace ACT.Tests;

/// <summary>Coverage for ACT.Policy, ACT.Risk, and ACT.Evidence modules.</summary>
public class PolicyRiskEvidenceTests
{
    // ---------- Shared builders ----------

    private static ScopeDefinition Scope(
        CheckCategory[]? allowed = null,
        CheckCategory[]? prohibited = null) =>
        new(
            ScopeId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "unit-test-operator",
            Organization: "unit-test-org",
            TargetType: TargetTypeKind.Localhost,
            AllowlistedTargets: ["localhost"],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https],
            PermittedPorts: [PortRange.Single(443)],
            RequestsPerSecond: 5,
            ConcurrencyLimit: 2,
            MaxRuntime: TimeSpan.FromMinutes(30),
            MaxRequests: 500,
            AllowedCategories: allowed ?? Enum.GetValues<CheckCategory>(),
            ProhibitedCategories: prohibited ?? [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "unit-test authorization statement");

    private static SecurityCheckMetadata Meta(
        CheckCategory category = CheckCategory.Http,
        SafetyLevel safety = SafetyLevel.SafeRequestOnly,
        PermissionRequirement permissions = PermissionRequirement.None,
        string id = "HTTP-SAMPLE-CHECK") =>
        new(
            Id: new CheckId(id),
            Name: "Sample check",
            Version: "1.0.0",
            Category: category,
            MaxEmittingSeverity: Severity.Informational,
            SafetyLevel: safety,
            RequiredPermissions: permissions,
            RequiredProtocols: new HashSet<ProtocolKind>(),
            SupportedTargetTypes: new HashSet<TargetTypeKind> { TargetTypeKind.Localhost },
            NetworkBehavior: new NetworkBehaviorProfile(1, 1, false, false, false),
            EvidenceTypesProduced: [],
            SupportsRemediation: false,
            SupportsRegressionTest: false,
            Description: "synthetic check metadata");

    private static RiskInput MaxRisk() => new(
        Severity.Critical, ConfidenceLevel.High, true, true, true, true, BusinessImpactLevel.Severe);

    private static RiskInput MinRisk() => new(
        Severity.Informational, ConfidenceLevel.Low, false, false, false, false, BusinessImpactLevel.Negligible);

    private static Cvss4Metrics Saturated => new(
        Cvss4AttackVector.Network,
        Cvss4PrivilegesRequired.None,
        Cvss4UserInteraction.None,
        Cvss4Impact.High,
        Cvss4Impact.High,
        Cvss4Impact.High,
        Cvss4Impact.High,
        Cvss4Impact.High,
        Cvss4Impact.High,
        Cvss4ExploitMaturity.Attacked);

    private static Finding FindingOf(
        double score,
        Severity severity = Severity.Medium,
        double confidence = 0.6,
        string title = "finding")
    {
        var now = DateTimeOffset.UtcNow;
        return new Finding(
            FindingId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            CheckId: CheckId.From("PRIOR-TEST"),
            TargetDisplay: "synthetic-target",
            AssetReference: null,
            Category: CheckCategory.Http,
            Title: title,
            Description: "description",
            TechnicalSeverity: severity,
            Confidence: ConfidenceLevel.Medium,
            ConfidenceScore: confidence,
            ExploitabilityIndicator: false,
            BusinessImpact: BusinessImpactLevel.Unknown,
            WhyItMatters: "why",
            TechnicalExplanation: "technical",
            Remediation: new RemediationGuidance("remediate", [], []),
            FirstSeenUtc: now,
            LastSeenUtc: now,
            Status: FindingStatus.New,
            Fingerprint: new FindingFingerprint(Guid.NewGuid().ToString("N")),
            RegressionTestId: null,
            CvssVector: null,
            CvssBaseScore: null)
        {
            PriorityScore = score
        };
    }

    private static StandardEvidenceRedactor Standard() => new(RedactionPolicy.Standard);

    private static StandardEvidenceRedactor Strict() => new(RedactionPolicy.Strict);

    // ---------- Policy evaluation ----------

    [Fact]
    public void ProhibitedCategoryWinsOverAllowedListAndEmergencyStop()
    {
        var stop = new EmergencyStop();
        var evaluator = new ScopePolicyEvaluator(stop);
        var scope = Scope(allowed: [CheckCategory.Http], prohibited: [CheckCategory.Http]);
        stop.Arm("operator halt");
        var decision = evaluator.Evaluate(scope, Meta());
        Assert.False(decision.Allowed);
        Assert.Equal(PolicyReasonCodes.CategoryProhibited, decision.ReasonCode);
    }

    [Fact]
    public void CategoryMissingFromAllowlistIsDenied()
    {
        var evaluator = new ScopePolicyEvaluator();
        var decision = evaluator.Evaluate(Scope(allowed: [CheckCategory.Tls]), Meta(category: CheckCategory.Http));
        Assert.False(decision.Allowed);
        Assert.Equal(PolicyReasonCodes.CategoryNotEnabled, decision.ReasonCode);
    }

    [Fact]
    public void EnabledSafeCheckIsAllowed()
    {
        var evaluator = new ScopePolicyEvaluator(allowActiveChecks: true);
        var decision = evaluator.Evaluate(Scope(), Meta(safety: SafetyLevel.ActiveNonDestructive));
        Assert.True(decision.Allowed);
        Assert.Equal(PolicyReasonCodes.Allowed, decision.ReasonCode);
    }

    [Fact]
    public void PermissionsOutsideGrantedMaskAreDenied()
    {
        var evaluator = new ScopePolicyEvaluator(grantedPermissions: PermissionRequirement.ReadRepositoryFiles);
        var decision = evaluator.Evaluate(Scope(), Meta(permissions: PermissionRequirement.OutboundNetworkToLocalTargets));
        Assert.False(decision.Allowed);
        Assert.Equal(PolicyReasonCodes.PermissionDenied, decision.ReasonCode);
    }

    [Fact]
    public void DefaultGrantCoversAllFourPermissionBits()
    {
        var evaluator = new ScopePolicyEvaluator();
        foreach (var bit in Enum.GetValues<PermissionRequirement>())
        {
            if (bit == PermissionRequirement.None)
            {
                continue;
            }

            var decision = evaluator.Evaluate(Scope(), Meta(permissions: bit));
            Assert.True(decision.Allowed, bit.ToString());
        }
    }

    [Fact]
    public void ActiveChecksAreDeniedUnlessExplicitlyEnabled()
    {
        var evaluator = new ScopePolicyEvaluator();
        var denied = evaluator.Evaluate(Scope(), Meta(safety: SafetyLevel.ActiveNonDestructive));
        Assert.False(denied.Allowed);
        Assert.Equal(PolicyReasonCodes.SafetyLevelExceeded, denied.ReasonCode);
    }

    [Fact]
    public void EmptyCategoryPolicyFailsClosed()
    {
        var evaluator = new ScopePolicyEvaluator();
        var exception = Assert.Throws<ActException>(
            () => evaluator.Evaluate(Scope(allowed: [], prohibited: []), Meta()));
        Assert.Equal(ErrorCategory.Configuration, exception.Category);
    }

    // ---------- Emergency stop ----------

    [Fact]
    public void ArmedEmergencyStopDeniesEveryCheck()
    {
        var stop = new EmergencyStop();
        var evaluator = new ScopePolicyEvaluator(stop);
        stop.Arm("halt everything");
        foreach (var category in Enum.GetValues<CheckCategory>())
        {
            var decision = evaluator.Evaluate(Scope(), Meta(category: category));
            Assert.False(decision.Allowed, category.ToString());
            Assert.Equal(PolicyReasonCodes.EmergencyStopArmed, decision.ReasonCode);
        }
    }

    [Fact]
    public void DisarmRestoresNormalEvaluation()
    {
        var stop = new EmergencyStop();
        var evaluator = new ScopePolicyEvaluator(stop);
        stop.Arm("halt");
        Assert.False(evaluator.Evaluate(Scope(), Meta()).Allowed);
        stop.Disarm("second-operator");
        var restored = evaluator.Evaluate(Scope(), Meta());
        Assert.True(restored.Allowed);
        Assert.Equal(PolicyReasonCodes.Allowed, restored.ReasonCode);
    }

    [Fact]
    public void EmergencyStopLatchTracksArmDisarmAndTokenCancellation()
    {
        var stop = new EmergencyStop();
        Assert.False(stop.IsArmed);
        var cancelled = false;
        using (stop.TokenSource.Token.Register(() => cancelled = true))
        {
            stop.Arm("incident detected");
            Assert.True(stop.IsArmed);
            Assert.Equal("incident detected", stop.Reason);
            Assert.True(stop.TokenSource.Token.IsCancellationRequested);
            Assert.True(cancelled);

            stop.Arm("second reason ignored");
            Assert.Equal("incident detected", stop.Reason);
        }

        stop.Disarm("operator");
        Assert.False(stop.IsArmed);
        Assert.Equal(string.Empty, stop.Reason);
        Assert.False(stop.TokenSource.Token.IsCancellationRequested);
    }

    [Fact]
    public void EmergencyStopSurvivesConcurrentUse()
    {
        var stop = new EmergencyStop();
        var reasons = new[] { "r0", "r1", "r2", "r3", "r4" };
        Parallel.For(0, 128, i =>
        {
            stop.Arm(reasons[i % reasons.Length]);
            var source = stop.TokenSource;
            _ = source.Token.IsCancellationRequested;
            _ = stop.IsArmed;
            stop.Disarm("concurrent-operator");
        });
        Assert.False(stop.IsArmed);
        Assert.False(stop.TokenSource.Token.IsCancellationRequested);
    }

    // ---------- Deterministic risk scorer ----------

    [Fact]
    public void ScorerHitsExactTableBoundaries()
    {
        Assert.Equal(100d, DeterministicRiskScorer.Score(MaxRisk()));
        Assert.Equal(5d, DeterministicRiskScorer.Score(MinRisk()));
    }

    [Fact]
    public void ScorerFollowsDocumentedWeightsExactly()
    {
        double Base() => DeterministicRiskScorer.Score(MinRisk());
        Assert.Equal(Base() + 10, DeterministicRiskScorer.Score(MinRisk() with { TechnicalSeverity = Severity.Low }));
        Assert.Equal(Base() + 20, DeterministicRiskScorer.Score(MinRisk() with { TechnicalSeverity = Severity.Medium }));
        Assert.Equal(Base() + 30, DeterministicRiskScorer.Score(MinRisk() with { TechnicalSeverity = Severity.High }));
        Assert.Equal(Base() + 40, DeterministicRiskScorer.Score(MinRisk() with { TechnicalSeverity = Severity.Critical }));
        Assert.Equal(Base() + 7, DeterministicRiskScorer.Score(MinRisk() with { Confidence = ConfidenceLevel.Medium }));
        Assert.Equal(Base() + 15, DeterministicRiskScorer.Score(MinRisk() with { Confidence = ConfidenceLevel.High }));
        Assert.Equal(Base() + 15, DeterministicRiskScorer.Score(MinRisk() with { ExploitabilityIndicator = true }));
        Assert.Equal(Base() + 10, DeterministicRiskScorer.Score(MinRisk() with { ExposedToNetwork = true }));
        Assert.Equal(Base() + 10, DeterministicRiskScorer.Score(MinRisk() with { Recurring = true }));
        Assert.Equal(Base() + 5, DeterministicRiskScorer.Score(MinRisk() with { RemediationAvailable = true }));
    }

    [Fact]
    public void ScorerIsPureAndDeterministic()
    {
        var input = MaxRisk();
        var first = DeterministicRiskScorer.Score(input);
        for (var i = 0; i < 50; i++)
        {
            Assert.Equal(first, DeterministicRiskScorer.Score(input));
        }
    }

    [Fact]
    public void ScorerNeverDecreasesWhenAnyComponentWorsens()
    {
        var severities = new[] { Severity.Informational, Severity.Low, Severity.Medium, Severity.High, Severity.Critical };
        var confidences = new[] { ConfidenceLevel.Low, ConfidenceLevel.Medium, ConfidenceLevel.High };
        foreach (var severity in severities)
        foreach (var confidence in confidences)
        {
            var input = new RiskInput(severity, confidence, false, false, false, false, BusinessImpactLevel.Unknown);
            var previous = DeterministicRiskScorer.Score(input);
            Assert.InRange(previous, 0, 100);
            Assert.True(DeterministicRiskScorer.Score(input with { ExploitabilityIndicator = true }) >= previous);
            Assert.True(DeterministicRiskScorer.Score(input with { ExposedToNetwork = true }) >= previous);
            Assert.True(DeterministicRiskScorer.Score(input with { Recurring = true }) >= previous);
            Assert.True(DeterministicRiskScorer.Score(input with { RemediationAvailable = true }) >= previous);
        }
    }

    // ---------- CVSS-v4-style estimator ----------

    [Fact]
    public void EstimatorReturnsNullForAnyUnknownMetric()
    {
        Cvss4Metrics?[] unknownVariants =
        [
            null,
            Saturated with { AttackVector = null },
            Saturated with { PrivilegesRequired = null },
            Saturated with { UserInteraction = null },
            Saturated with { VulnerableConfidentiality = null },
            Saturated with { VulnerableIntegrity = null },
            Saturated with { VulnerableAvailability = null },
            Saturated with { SubsequentConfidentiality = null },
            Saturated with { SubsequentIntegrity = null },
            Saturated with { SubsequentAvailability = null },
            Saturated with { ExploitMaturity = null },
            Saturated with { VulnerableIntegrity = (Cvss4Impact)99 },
            Saturated with { AttackVector = (Cvss4AttackVector)42 }
        ];
        foreach (var variant in unknownVariants)
        {
            Assert.Null(Cvss4Estimator.Estimate(variant));
        }
    }

    [Fact]
    public void EstimatorSpansFullRange()
    {
        Assert.Equal(10d, Cvss4Estimator.Estimate(Saturated)!.Value);
        var worst = new Cvss4Metrics(
            Cvss4AttackVector.Physical,
            Cvss4PrivilegesRequired.High,
            Cvss4UserInteraction.Required,
            Cvss4Impact.None,
            Cvss4Impact.None,
            Cvss4Impact.None,
            Cvss4Impact.None,
            Cvss4Impact.None,
            Cvss4Impact.None,
            Cvss4ExploitMaturity.Unreported);
        Assert.Equal(0d, Cvss4Estimator.Estimate(worst)!.Value);
    }

    [Fact]
    public void EstimatorIsMonotoneInEveryMetric()
    {
        static double Score(Cvss4Metrics metrics) => Cvss4Estimator.Estimate(metrics)!.Value;

        var prior = double.NegativeInfinity;
        foreach (var vector in new[]
                 {
                     Cvss4AttackVector.Physical, Cvss4AttackVector.Local, Cvss4AttackVector.Adjacent, Cvss4AttackVector.Network
                 })
        {
            var score = Score(Saturated with { AttackVector = vector });
            Assert.True(score >= prior, "AV ladder regressed.");
            prior = score;
        }

        prior = double.NegativeInfinity;
        foreach (var privileges in new[] { Cvss4PrivilegesRequired.High, Cvss4PrivilegesRequired.Low, Cvss4PrivilegesRequired.None })
        {
            var score = Score(Saturated with { PrivilegesRequired = privileges });
            Assert.True(score >= prior, "PR ladder regressed.");
            prior = score;
        }

        prior = double.NegativeInfinity;
        foreach (var interaction in new[] { Cvss4UserInteraction.Required, Cvss4UserInteraction.None })
        {
            var score = Score(Saturated with { UserInteraction = interaction });
            Assert.True(score >= prior, "UI ladder regressed.");
            prior = score;
        }

        prior = double.NegativeInfinity;
        foreach (var maturity in new[]
                 {
                     Cvss4ExploitMaturity.Unreported, Cvss4ExploitMaturity.NotDefined,
                     Cvss4ExploitMaturity.PocReported, Cvss4ExploitMaturity.Attacked
                 })
        {
            var score = Score(Saturated with { ExploitMaturity = maturity });
            Assert.True(score >= prior, "ExploitMaturity ladder regressed.");
            prior = score;
        }

        void CheckImpact(string axis, Func<Cvss4Impact, Cvss4Metrics> project)
        {
            var localPrior = double.NegativeInfinity;
            foreach (var impact in new[] { Cvss4Impact.None, Cvss4Impact.Low, Cvss4Impact.High })
            {
                var score = Score(project(impact));
                Assert.True(score >= localPrior, $"{axis} ladder regressed.");
                localPrior = score;
            }
        }

        CheckImpact("VC", v => Saturated with { VulnerableConfidentiality = v });
        CheckImpact("VI", v => Saturated with { VulnerableIntegrity = v });
        CheckImpact("VA", v => Saturated with { VulnerableAvailability = v });
        CheckImpact("SC", v => Saturated with { SubsequentConfidentiality = v });
        CheckImpact("SI", v => Saturated with { SubsequentIntegrity = v });
        CheckImpact("SA", v => Saturated with { SubsequentAvailability = v });
    }

    // ---------- Finding prioritizer ----------

    [Fact]
    public void PrioritizerOrdersByScoreThenSeverityThenConfidenceThenTitleOrdinal()
    {
        var alpha = FindingOf(50, Severity.Low, 0.3, "alpha");
        var bravo = FindingOf(80, Severity.High, 0.9, "bravo");
        var charlie = FindingOf(50, Severity.High, 0.3, "charlie");
        var delta = FindingOf(50, Severity.High, 0.9, "delta");
        var echo = FindingOf(50, Severity.High, 0.9, "Echo");

        var ordered = FindingPrioritizer.Prioritize([echo, alpha, delta, charlie, bravo]);
        Assert.Equal(
            ["bravo", "Echo", "delta", "charlie", "alpha"],
            ordered.Select(f => f.Title).ToArray());
    }

    [Fact]
    public void PrioritizerIsStableForIdenticalKeys()
    {
        var first = FindingOf(10, title: "same");
        var second = FindingOf(10, title: "same");
        var ordered = FindingPrioritizer.Prioritize([first, second]);
        Assert.Same(first, ordered[0]);
        Assert.Same(second, ordered[1]);
    }

    // ---------- Redaction vectors ----------

    [Fact]
    public void JwtTokensAreRedacted()
    {
        var redacted = Standard().Redact(
            "payload access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c end");
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiJ9", redacted);
        Assert.DoesNotContain("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c", redacted);
        Assert.Matches(@"access_token=\[REDACTED:sha256:[0-9a-f]{12}\]", redacted);
        Assert.EndsWith(" end", redacted);
    }

    [Fact]
    public void BearerTokensAreRedacted()
    {
        var redacted = Standard().Redact("response header echo: Bearer AbCdEf123456.-_~Ok tail");
        Assert.DoesNotContain("AbCdEf123456", redacted);
        Assert.Matches(@"Bearer \[REDACTED:sha256:[0-9a-f]{12}\]", redacted);
        Assert.EndsWith(" tail", redacted);
    }

    [Fact]
    public void AwsAccessKeysAreRedacted()
    {
        var redacted = Standard().Redact("creds AKIAIOSFODNN7EXAMPLE embedded");
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", redacted);
        Assert.Matches(@"\[REDACTED:sha256:[0-9a-f]{12}\]", redacted);
        Assert.Contains("embedded", redacted);
    }

    [Fact]
    public void CookieHeadersAreSensitiveAndFingerprinted()
    {
        var redactor = Standard();
        Assert.True(redactor.IsSensitiveHeader("Set-Cookie"));
        Assert.True(redactor.IsSensitiveHeader("cookie"));
        Assert.True(redactor.IsSensitiveHeader("X-API-Key"));
        Assert.True(redactor.IsSensitiveHeader("Proxy-Authorization"));
        Assert.False(redactor.IsSensitiveHeader("Accept"));

        var redacted = redactor.Redact("Set-Cookie: session=0123456789abcdef; Path=/");
        Assert.DoesNotContain("0123456789abcdef", redacted);
        Assert.StartsWith("Set-Cookie: [REDACTED:sha256:", redacted);
    }

    [Fact]
    public void PemPrivateKeysAreRedactedEntirely()
    {
        const string pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234\nqwertyuiopasdfgh\n-----END RSA PRIVATE KEY-----";
        var redacted = Standard().Redact($"before {pem} after");
        Assert.DoesNotContain("BEGIN", redacted);
        Assert.DoesNotContain("MIIEpAIBAAKCAQEA1234", redacted);
        Assert.Matches(@"\[REDACTED:sha256:[0-9a-f]{12}\]", redacted);
        Assert.EndsWith(" after", redacted);
    }

    [Fact]
    public void AuthorizationHeaderLineIsReplacedWithLengthMarker()
    {
        const string headerValue = "Bearer eyJhbGciOiJub25lIn0.eyJhIjoxfQ.sig-segment";
        var redacted = Standard().Redact($"GET / HTTP/1.1\nAuthorization: {headerValue}\nHost: lab.test");
        Assert.DoesNotContain("sig-segment", redacted);
        Assert.Contains($"REDACTED(len={headerValue.Length})", redacted);
        Assert.Contains("Host: lab.test", redacted);
    }

    [Fact]
    public void SecretQueryParametersAreRedactedWithoutTouchingNeighbors()
    {
        var redacted = Standard().Redact("/login?user=alice&api_key=kitten99&next=%2Fhome");
        Assert.DoesNotContain("kitten99", redacted);
        Assert.Contains("user=alice", redacted);
        Assert.Contains("next=%2Fhome", redacted);
    }

    [Fact]
    public void LongAssignedSecretsWithKeywordNamesAreRedacted()
    {
        var redacted = Standard().Redact("config db_password = \"rotateme-0123456789-abcdefghijklmnop\" retries=3");
        Assert.DoesNotContain("rotateme-0123456789", redacted);
        Assert.Contains("retries=3", redacted);

        var shortValue = Standard().Redact("label: keyboard-map=abc");
        Assert.Contains("keyboard-map=abc", shortValue);
    }

    // ---------- Strict-mode allowlist ----------

    [Fact]
    public void StrictModeRedactsEveryHeaderExceptAllowlist()
    {
        const string raw = "Host: internal.lab\nContent-Type: application/json\nServer: unit-test\nX-Trace-Context: trace-abc-123";
        var redacted = Strict().Redact(raw);
        Assert.Contains("Host: internal.lab", redacted);
        Assert.Contains("Content-Type: application/json", redacted);
        Assert.Contains("Server: unit-test", redacted);
        Assert.DoesNotContain("trace-abc-123", redacted);
        Assert.Contains("X-Trace-Context: [REDACTED:sha256:", redacted);
    }

    [Fact]
    public void StandardModeLeavesOrdinaryHeadersAlone()
    {
        const string raw = "X-Trace-Context: trace-abc-123\nAccept: text/html";
        Assert.Equal(raw, Standard().Redact(raw));
    }

    [Fact]
    public void StrictModeStillSpecialCasesAuthorizationLengthMarker()
    {
        const string headerValue = "Bearer tok123456789";
        var redacted = Strict().Redact($"Authorization: {headerValue}");
        Assert.Equal($"Authorization: REDACTED(len={headerValue.Length})", redacted);
    }

    [Fact]
    public void IdenticalSecretsProduceIdenticalStableFingerprints()
    {
        const string secret = "token=abcdefghijklmnopqrstuvwxyz012345";
        var first = Standard().Redact(secret);
        var second = Standard().Redact(secret);
        Assert.Equal(first, second);

        var other = Standard().Redact("token=zyxwvutsrqponmlkjihgfedcba543210");
        Assert.NotEqual(first, other);
    }

    // ---------- Evidence factory ----------

    [Fact]
    public void FactoryAppliesRedactionAndStampsCaptureTime()
    {
        var factory = new EvidenceFactory(Standard());
        var headerValue = "Bearer secret-value-123456";
        var before = DateTimeOffset.UtcNow;
        var item = factory.Create(
            Guid.NewGuid(), EvidenceKind.HttpHeaders, "Authorization", headerValue,
            CheckId.From("FACTORY-CHECK"), CorrelationId.New());
        var after = DateTimeOffset.UtcNow;

        Assert.Equal($"REDACTED(len={headerValue.Length})", item.RedactedValue);
        Assert.InRange(item.CapturedAtUtc.Ticks, before.Ticks, after.Ticks);
        Assert.Equal("Authorization", item.Key);
        Assert.Empty(item.Attributes);
    }

    [Fact]
    public void FactoryRejectsMissingKeys()
    {
        var factory = new EvidenceFactory(Standard());
        Assert.Throws<ArgumentException>(() =>
            factory.Create(Guid.NewGuid(), EvidenceKind.HttpHeaders, "", "v", CheckId.From("X"), CorrelationId.New()));
        Assert.Throws<ArgumentException>(() =>
            factory.Create(Guid.NewGuid(), EvidenceKind.HttpHeaders, "   ", "v", CheckId.From("X"), CorrelationId.New()));
        Assert.Throws<ArgumentException>(() =>
            factory.Create(Guid.NewGuid(), EvidenceKind.HttpHeaders, null!, "v", CheckId.From("X"), CorrelationId.New()));
    }

    [Fact]
    public void FactoryRedactsSensitiveHeadersWholesaleEvenForOpaqueValues()
    {
        var factory = new EvidenceFactory(Standard());
        var item = factory.Create(
            Guid.NewGuid(), EvidenceKind.HttpHeaders, "Set-Cookie", "sid=opaque-session-value; HttpOnly",
            CheckId.From("FACTORY-CHECK"), CorrelationId.New());

        Assert.DoesNotContain("opaque-session-value", item.RedactedValue);
        Assert.StartsWith("[REDACTED:sha256:", item.RedactedValue);
    }

    // ---------- Retention ----------

    [Fact]
    public void RetentionBoundaryIsExclusive()
    {
        var factory = new EvidenceFactory(Standard());
        var item = factory.Create(
            Guid.NewGuid(), EvidenceKind.StatusCode, "status", "200 OK",
            CheckId.From("RETENTION-CHECK"), CorrelationId.New());
        var captured = item.CapturedAtUtc;

        Assert.False(EvidenceRetention.IsExpired(item, TimeSpan.FromDays(30), captured.AddDays(30)));
        Assert.True(EvidenceRetention.IsExpired(item, TimeSpan.FromDays(30), captured.AddDays(31)));
        Assert.True(EvidenceRetention.IsExpired(item, TimeSpan.Zero, captured.AddSeconds(1)));
    }
}
